# AGENTS.md

## Project Overview

crcauthlib is a Go library that provides JWT, X.509 certificate, and HTTP Basic authentication validation for Red Hat Insights Crown (CRC) services. It automatically detects the authentication method from incoming HTTP requests and returns structured identity information including user details, service account data, and entitlements. The library is distributed as a Go module (`github.com/redhatinsights/crcauthlib`) and imported via `go get`.

## Dependencies

**Runtime:**
- `github.com/golang-jwt/jwt/v4` (v4.5.2) - JWT token processing
- `github.com/redhatinsights/platform-go-middlewares/v2` (v2.1.0) - Identity types

**Dev/Test:**
- `github.com/stretchr/testify` (v1.11.1) - Testing assertions
- `golangci-lint` (v9.2.1) - Comprehensive linting (48 linters)

## Development Commands

```bash
# Install dependencies
go mod download

# Run tests (with race detector - same as CI)
make test

# Generate coverage report
make coverage

# Run linting (same as CI uses)
make lint

# Default target (runs tests)
make all
```

**CI Runs**: `make lint` + `make test` on Go 1.25 & 1.26, ubuntu + macOS

## Architecture

- **Package structure**: Single package `crcauthlib` + `deps` subpackage for HTTP interface
- **Entry point**: `NewCRCAuthValidator(config)` → `ProcessRequest(r)` auto-detects auth method
- **Main types**: `CRCAuthValidator` (main validator), `XRHID` (identity + entitlements), three identity types (User/ServiceAccount/System)
- **Deep detail**: See [ARCHITECTURE.md][architecture] for design decisions, public key management, JWT claims handling, and security considerations

## Code Style

- **Linter**: golangci-lint v9.2.1 with 48 enabled linters (see `.golangci.yml`)
- **Formatter**: gofmt + goimports (enforced by linter)
- **Line length**: No strict limit, but gofmt's natural wrapping applies
- **Go version**: 1.25 minimum (specified in go.mod)
- **Key rules**:
  - gocyclo: min complexity 15
  - Test files: errcheck, goconst, gocyclo, gosec disabled
  - Only new issues flagged in CI (not entire codebase)

## Common Mistakes

1. **Wrong HTTP client in tests**: The library uses `deps.HTTP` interface (not `http.DefaultClient`). Test code MUST inject a mock via `deps.HTTP = mockClient` before calling validator methods. The global state means tests cannot run in parallel if they mutate `deps.HTTP`.

2. **Assuming public key is pre-loaded**: The public key is lazy-loaded on first JWT validation. Don't expect `crc.verifyKey` to be populated immediately after `NewCRCAuthValidator()`. The first validation call will fetch it (and may fail if BOP is unreachable or JWTPEM is unset).

3. **Using inline logging libraries**: The library intentionally uses `fmt.Println()` for debug output (not structured logging). Don't add dependencies on logrus/zap/zerolog. Consuming applications should wrap the library if they need structured logging.

4. **Forgetting Basic Auth requires BOP**: All three auth methods (JWT, Certificate, Basic) require `config.BOPUrl` to be set, except JWT which can fall back to `JWTPEM` env var. Certificate and Basic auth will always fail if `BOPUrl` is empty.

5. **Editing legacy config files**: The `.golangci.yml` file is the ONLY active linter config. Don't create `.golangci-lint.yml` or other variants — they won't be used.

6. **Mixing identity types**: The three identity types (User, ServiceAccount, System) populate different fields in `identity.XRHID`. Don't assume `User` field is always populated — check `Identity.Type` first. ServiceAccount identities have no User field.

## Testing

**Test file**: `crcauthlib_test.go` (469 lines)  
**Test data**: `test_files/` contains JWT samples, RSA key pairs, and user JSON fixtures

**How to run**:
```bash
make test          # Run with race detector (recommended)
go test ./...      # Standard test run
make coverage      # Generate coverage.out
```

**Test conventions**:
- Use `testify/assert` for assertions
- Mock HTTP client via `deps.HTTP` global
- Private key in `test_files/private.pem` is used to sign test JWTs
- Test JWTs use the `CreateJWT()` helper function

**What CI tests**:
- Go 1.25 and 1.26
- Ubuntu + macOS platforms
- Race detector enabled
- Lint must pass before tests run

[architecture]: ARCHITECTURE.md
