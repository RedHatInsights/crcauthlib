# Architecture

This document describes the internal architecture, design decisions, and
implementation details of `crcauthlib`. It is the authoritative technical
reference for contributors and agents working on this codebase.

For installation, usage examples, and development commands, see the [README][readme].

---

## Table of Contents

- [Overview](#overview)
- [File Structure](#file-structure)
- [Core Types](#core-types)
- [Authentication Strategy](#authentication-strategy)
- [Processing Flows](#processing-flows)
- [Public Key Management](#public-key-management)
- [Identity Type System](#identity-type-system)
- [JWT Claims Handling](#jwt-claims-handling)
- [External Dependencies](#external-dependencies)
- [Dependency Injection and Testability](#dependency-injection-and-testability)
- [Error Handling Philosophy](#error-handling-philosophy)
- [Type Safety and Ecosystem Alignment](#type-safety-and-ecosystem-alignment)
- [Security Considerations](#security-considerations)
- [Known Limitations](#known-limitations)

---

## Overview

`crcauthlib` is a Go library that provides authentication and authorization for
Red Hat Insights Crown (CRC) services. It is consumed as a dependency by
service applications -- it is not a standalone application itself.

The library accepts an `*http.Request`, auto-detects which authentication method
the caller used, validates the credentials, and returns a populated
`identity.XRHID` struct that downstream services use for access control.

---

## File Structure

```
crcauthlib/
├── crcauthlib.go           # Main validator logic (~467 lines)
├── crcauthlib_test.go      # Test suite with mock HTTP client
├── deps/
│   └── deps.go             # HTTP client interface for dependency injection
├── test_files/
│   ├── jwt.txt             # Sample JWT token for tests
│   ├── private.pem         # RSA private key for signing test JWTs
│   ├── public.pem          # RSA public key for verifying test JWTs
│   └── test_user.json      # Sample user JSON response for mock BOP
├── go.mod
└── go.sum
```

All validator logic lives in a single file (`crcauthlib.go`). The `deps/`
package exists solely to enable test-time dependency injection of the HTTP
client.

---

## Core Types

### CRCAuthValidator

The central struct. Holds configuration, the raw PEM string, and the parsed RSA
public key. Created via `NewCRCAuthValidator()`.

```go
type CRCAuthValidator struct {
    config    *ValidatorConfig   // BOPUrl and future config
    pem       string             // Raw PEM string (cached after first load)
    verifyKey *rsa.PublicKey     // Parsed RSA key (cached after first load)
}
```

### ValidatorConfig

Minimal configuration -- currently only `BOPUrl`. Passed to
`NewCRCAuthValidator()` at construction time.

### XRHID (local)

The library defines its own `XRHID` wrapper that pairs `identity.Identity`
(from [platform-go-middlewares][middlewares]) with a local `Entitlement` map.
This local type is used only for internal deserialization; the public API
returns `*identity.XRHID` from the platform-go-middlewares package.

### Supporting Types

| Type           | Purpose                                                     |
|----------------|-------------------------------------------------------------|
| `Registration` | Deserialized response from BOP `/v1/check_registration`     |
| `User`         | Deserialized user payload from BOP `/v1/auth`               |
| `Resp`         | Envelope wrapping `User` and `Mechanism` from BOP responses |
| `Entitlement`  | Local struct with `IsTrial` and `IsEntitled` booleans       |

---

## Authentication Strategy

`ProcessRequest()` uses a **priority-based auto-detection** pattern. It
inspects the incoming `*http.Request` and selects the first matching method in
this fixed order:

| Priority | Method                  | Detection Logic                                | Auth Type Constant |
|----------|-------------------------|------------------------------------------------|--------------------|
| 1        | TLS client certificate  | `r.TLS != nil && len(r.TLS.PeerCertificates) > 0` | `"cert-auth"`    |
| 2        | HTTP Basic Auth         | `r.BasicAuth()` returns `ok == true`           | `"basic-auth"`     |
| 3        | JWT Bearer header       | `Authorization` header contains `"Bearer"`     | `"jwt-auth"`       |
| 4        | JWT `cs_jwt` cookie     | Cookie named `cs_jwt` exists                   | `"jwt-auth"`       |

**Why this order?**

- TLS certificates are checked first because they are the strongest form of
  authentication and are typically used by system-to-system communication.
- Basic auth is checked second as a simple, well-understood mechanism.
- JWT via header is the most common path for browser and API clients.
- JWT via cookie is the final fallback, supporting the Console Services
  (`cs_jwt`) cookie-based authentication flow.

If none of these conditions match, `ProcessRequest()` returns a
`"bad auth type"` error.

**Design note:** The detection is mutually exclusive -- once a method matches,
no further methods are attempted. This means a request carrying both a TLS
certificate and a Bearer token will always be processed as a certificate
request.

---

## Processing Flows

### JWT Processing

```
Request arrives
  │
  ├─ Extract token (from Authorization header, cs_jwt cookie, or raw string)
  │
  ├─ Lazy-load RSA public key if not already cached (see Public Key Management)
  │
  ├─ Validate JWT signature
  │    └─ Reject if signing method is not *jwt.SigningMethodRSA
  │
  ├─ Parse claims into jwt.MapClaims
  │
  ├─ Check service_account claim
  │    ├─ "true"  → Build ServiceAccount identity
  │    └─ else    → Build User identity
  │
  ├─ Extract entitlements
  │    ├─ Try newEntitlements (array of JSON strings) first
  │    └─ Fall back to entitlements (single JSON string)
  │
  └─ Return populated *identity.XRHID
```

Three entry points converge on `buildIdent()`:

- `processJWTHeaderRequest()` -- uses `request.ParseFromRequest()` with
  `AuthorizationHeaderExtractor`
- `processJWTCookieRequest()` -- reads the `cs_jwt` cookie value, then
  delegates to `ValidateJWTToken()`
- `processJWTToken()` -- accepts a raw token string directly

### Certificate Processing

```
Request arrives with r.TLS.PeerCertificates
  │
  ├─ Extract Subject.CommonName from the first peer certificate
  │
  ├─ POST to BOP: config.BOPUrl + "/v1/check_registration"
  │    └─ CN sent via x-rh-check-reg header (GET request, not POST)
  │
  ├─ Check response status (must be 200 OK)
  │
  ├─ Unmarshal response body into Registration struct
  │
  └─ Build System identity with:
       ├─ OrgID from registration
       ├─ CommonName from certificate
       ├─ CertType = "system"
       ├─ AuthType = "cert-auth"
       └─ Type = "System"
```

### Basic Auth Processing

```
Request arrives with Basic Auth credentials
  │
  ├─ Create GET request to BOP: config.BOPUrl + "/v1/auth"
  │    └─ Forward username/password via SetBasicAuth()
  │
  ├─ Check response status (must be 200 OK)
  │
  ├─ Unmarshal response body into Resp struct
  │
  ├─ If user has entitlements string, unmarshal it separately
  │
  └─ Build User identity with:
       ├─ All user fields from BOP response
       ├─ AuthType = "basic-auth"
       └─ Type from BOP response (typically "User")
```

---

## Public Key Management

The `grabVerify()` method implements a **two-tier fallback** strategy for
obtaining the RSA public key used to verify JWT signatures:

1. **Primary: BOP endpoint** -- If `config.BOPUrl` is set, fetch the key from
   `BOPUrl + "/v1/jwt"`. The response body is expected to be the raw
   Base64-encoded key (without PEM headers); `grabVerify()` wraps it in
   `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` before parsing.

2. **Fallback: Environment variable** -- If `BOPUrl` is empty, read the full
   PEM from the `JWTPEM` environment variable.

### Lazy Loading

The public key is **not** fetched at validator construction time.
`NewCRCAuthValidator()` returns immediately without any network calls. The key
is fetched on the first call to any validation method (`ValidateJWTToken`,
`ValidateJWTHeaderRequest`, `ValidateJWTCookieRequest`), each of which checks
`if crc.verifyKey == nil` and calls `grabVerify()` if needed.

**Tradeoff:** Lazy loading allows validators to be created without network
access (useful in tests and during application startup), but the first
validation request pays the cost of a network round-trip to fetch the key.

### Caching

Once loaded and parsed, the key is cached in `crc.verifyKey` for the lifetime
of the `CRCAuthValidator` instance. There is no TTL, refresh interval, or
cache invalidation mechanism.

---

## Identity Type System

The library distinguishes between **three identity types**, each populating
different fields in the `identity.XRHID` struct:

### User Identity

- **Source:** JWT tokens (when `service_account` claim is not `"true"`) or
  Basic Auth via BOP
- **Identity.Type:** `"User"`
- **Populated fields:** `Identity.User.*` (Username, Email, FirstName,
  LastName, Active, OrgAdmin, Internal, Locale, UserID)

### ServiceAccount Identity

- **Source:** JWT tokens where the `service_account` claim equals `"true"`
- **Identity.Type:** `"ServiceAccount"`
- **Populated fields:** `Identity.ServiceAccount.*` (Username is constructed
  as `"service-account-" + client_id`, ClientId from the `client_id` claim)
- **Notable:** No `User` struct is populated; `AccountNumber` is not set

### System Identity

- **Source:** TLS client certificates validated against BOP
- **Identity.Type:** `"System"`
- **Populated fields:** `Identity.System.*` (CommonName from the certificate
  subject, CertType = `"system"`)
- **Notable:** Uses `"cert-auth"` as AuthType rather than `"jwt-auth"`

---

## JWT Claims Handling

### Entitlement Formats

The library supports **two entitlement claim formats** for backward
compatibility:

1. **New format (`newEntitlements`):** An array of JSON strings. Each element
   is a key-value fragment like `"\"insights\": {\"is_entitled\": true}"`.
   These are joined with commas and wrapped in `{}` before unmarshaling.

2. **Legacy format (`entitlements`):** A single JSON string containing the
   entire entitlements object.

`buildIdent()` tries the new format first via `getArrayString()`. If that
returns `nil`, it falls back to the legacy format via `getStringClaim()`.

**Why both?** Backward compatibility with older JWT issuers that embed
entitlements as a single string claim rather than the newer array format.

### Claim Extraction Helpers

Three helper functions provide safe claim extraction with sensible defaults:

| Function          | Returns   | Default on missing/wrong type |
|-------------------|-----------|-------------------------------|
| `getStringClaim`  | `string`  | `"unknown"`                   |
| `getBoolClaim`    | `bool`    | `false`                       |
| `getArrayString`  | `[]string`| `nil`                         |

These are package-private functions that operate on `jwt.MapClaims`.

---

## External Dependencies

### BOP (Back Office Platform) Service

BOP is Red Hat's centralized user and system registration service. `crcauthlib`
depends on BOP for three operations:

| Operation            | HTTP Method | Endpoint                   | Input                        | Output             |
|----------------------|-------------|----------------------------|------------------------------|--------------------|
| Certificate auth     | GET         | `/v1/check_registration`   | `x-rh-check-reg` header (CN)| `Registration` JSON|
| Basic auth           | GET         | `/v1/auth`                 | Basic Auth header            | `Resp` JSON        |
| JWT public key fetch | GET         | `/v1/jwt`                  | None                         | Base64 key body    |

All BOP calls use the URL from `ValidatorConfig.BOPUrl` as the base.

### Go Module Dependencies

| Dependency                                            | Purpose                        |
|-------------------------------------------------------|--------------------------------|
| [github.com/golang-jwt/jwt/v4][jwt]                  | JWT parsing and validation     |
| [github.com/redhatinsights/platform-go-middlewares/v2][middlewares] | Identity type definitions |
| [github.com/stretchr/testify][testify]                | Test assertions (test only)    |

---

## Dependency Injection and Testability

The `deps` package (`deps/deps.go`) defines an `HTTPClient` interface:

```go
type HTTPClient interface {
    Do(req *http.Request) (*http.Response, error)
    Get(url string) (*http.Response, error)
}
```

The package-level variable `deps.HTTP` is initialized to `&http.Client{}` in
an `init()` function. Tests override this variable with a `MockHTTP` struct
that returns canned responses, allowing all BOP interactions to be tested
without network access.

**Design decision:** Using a package-level variable rather than constructor
injection keeps the public API simple (no need to pass an HTTP client to
`NewCRCAuthValidator`), at the cost of global mutable state. This is an
acceptable tradeoff for a library of this scope, but it means tests that
modify `deps.HTTP` are not safe to run in parallel without additional
synchronization.

---

## Error Handling Philosophy

The library uses **`fmt.Println` debug logging** to stdout rather than
structured logging or a logging interface. This is a deliberate choice:

- **Simplicity:** The library avoids taking a dependency on any logging
  framework, which would force consuming applications into a specific logging
  ecosystem.
- **Consumer responsibility:** Applications that import this library are
  expected to add their own logging middleware around calls to
  `ProcessRequest()` and `ProcessToken()`.

Errors are returned as standard Go `error` values using `errors.New()` and
`fmt.Errorf()` with `%w` wrapping where appropriate. The library does not
define custom error types.

**Tradeoff:** The stdout logging is useful during development but is not
compatible with structured logging systems (JSON, logrus, zap, etc.) that
production services typically use.

---

## Type Safety and Ecosystem Alignment

The library uses identity types from
[platform-go-middlewares/v2][middlewares] (`identity.XRHID`, `identity.Identity`,
`identity.User`, `identity.System`, `identity.ServiceAccount`, etc.) rather
than defining its own identity structs.

This ensures **cross-service compatibility** within the Red Hat Insights
ecosystem -- any service that imports `platform-go-middlewares` can consume
the identity structs produced by `crcauthlib` without type conversion.

The library also defines a local `XRHID` struct (with a local `Entitlement`
map), but the public API methods return `*identity.XRHID` from the shared
package.

---

## Security Considerations

- **RSA-only signature validation:** The JWT validation callback explicitly
  checks that `token.Method` is `*jwt.SigningMethodRSA`. Any other algorithm
  (including HMAC) is rejected with an `"unexpected signing method"` error.
  This prevents [key confusion attacks][key-confusion] where an attacker
  signs a token with HMAC using the public key as the secret.

- **TLS certificate validation:** Certificate authentication relies on Go's
  built-in `crypto/tls` and `crypto/x509` packages for the TLS handshake.
  The library itself does not perform certificate chain validation -- it
  extracts the Common Name and delegates registration checks to BOP.

- **Stateless validation:** No credentials, tokens, or session state are
  cached between requests. Each call to `ProcessRequest()` performs a full
  validation cycle. (The RSA public key is cached, but that is not a
  credential.)

- **No credential logging:** Although the library uses `fmt.Println` for
  debug output, it does not log tokens, passwords, or certificate contents.

---

## Known Limitations

1. **No async public key refresh.** Once the RSA public key is loaded and
   cached in `crc.verifyKey`, it is never refreshed. If the signing key is
   rotated, the validator must be recreated or the application restarted.

2. **No circuit breaker.** BOP service failures cause all certificate and
   Basic Auth requests to fail immediately. There is no retry logic, fallback
   behavior, or circuit breaker pattern.

3. **stdout logging.** Debug output via `fmt.Println` is not compatible with
   structured logging systems and cannot be disabled or redirected without
   replacing stdout.

4. **No request timeout configuration.** The default `http.Client` used by
   `deps.HTTP` has no explicit timeout set. Long-running or hung BOP
   requests will block the calling goroutine indefinitely unless the
   consumer overrides `deps.HTTP` with a configured client.

5. **Global HTTP client state.** `deps.HTTP` is a package-level variable,
   which means concurrent tests that override it may interfere with each
   other. Tests should not be run in parallel if they modify `deps.HTTP`.

6. **No token revocation checking.** JWT validation only checks the
   signature and standard claims (e.g., expiration). There is no call to a
   revocation list or introspection endpoint.

---

[readme]: README.md
[jwt]: https://github.com/golang-jwt/jwt
[middlewares]: https://github.com/redhatinsights/platform-go-middlewares
[testify]: https://github.com/stretchr/testify
[key-confusion]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
