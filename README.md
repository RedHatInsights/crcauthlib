# crcauthlib

A Go library for authentication and authorization in Red Hat Insights Crown (CRC) applications. Supports JWT tokens, TLS client certificates, and HTTP Basic authentication.

## Overview

`crcauthlib` provides a unified interface for validating authentication credentials and extracting user identity information in Red Hat Insights services. It automatically detects the authentication method used in incoming requests and validates them accordingly.

**Supported authentication methods:**
- JWT (JSON Web Tokens) via Authorization header or `cs_jwt` cookie
- TLS client certificates
- HTTP Basic authentication

## Installation

### Prerequisites

- Go 1.25 or later

### Install the library

```bash
go get github.com/redhatinsights/crcauthlib
```

## Usage

### Basic Setup

Create a validator and process incoming HTTP requests:

```go
package main

import (
    "net/http"
    "github.com/redhatinsights/crcauthlib"
)

func main() {
    // Create validator with optional BOP URL for fetching JWT public keys
    config := &crcauthlib.ValidatorConfig{
        BOPUrl: "https://sso.redhat.com/auth/realms/redhat-external",
    }
    validator := crcauthlib.NewCRCAuthValidator(config)

    http.HandleFunc("/api/endpoint", func(w http.ResponseWriter, r *http.Request) {
        // Process request and extract identity
        xrhid, err := validator.ProcessRequest(r)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Use identity information
        username := xrhid.Identity.User.Username
        accountNumber := xrhid.Identity.AccountNumber
        
        // Check entitlements
        if xrhid.Entitlements.Insights.IsEntitled {
            // User has access
        }
    })

    http.ListenAndServe(":8080", nil)
}
```

### JWT Token Validation

Validate JWT tokens directly:

```go
// Validate token string
xrhid, err := validator.ProcessToken(tokenString)
if err != nil {
    // Handle validation error
}

// Validate JWT from Authorization header
xrhid, err := validator.ValidateJWTHeaderRequest(request)

// Validate JWT from cs_jwt cookie
xrhid, err := validator.ValidateJWTCookieRequest(request)
```

### Configuration

The library supports two methods for providing the JWT public key:

1. **BOP URL** (recommended): Specify a URL to fetch the public key dynamically
   ```go
   config := &crcauthlib.ValidatorConfig{
       BOPUrl: "https://sso.redhat.com/auth/realms/redhat-external",
   }
   ```

2. **Environment variable**: Set `JWTPEM` with a PEM-encoded public key
   ```bash
   export JWTPEM="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
   ```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `CRCAuthValidator` | Main validator for processing authentication requests |
| `ValidatorConfig` | Configuration with optional BOPUrl |
| `XRHID` | Extended Red Hat Identity containing user identity and entitlements |
| `User` | User identity details (username, email, etc.) |
| `Entitlement` | Trial/entitled status for services |
| `Registration` | User registration data |

### Main Functions

```go
// Create a new validator
func NewCRCAuthValidator(config *ValidatorConfig) *CRCAuthValidator

// Auto-detect and process authentication from HTTP request
func (v *CRCAuthValidator) ProcessRequest(r *http.Request) (*XRHID, error)

// Process a JWT token string directly
func (v *CRCAuthValidator) ProcessToken(tokenString string) (*XRHID, error)

// Validate JWT from specific sources
func (v *CRCAuthValidator) ValidateJWTToken(tokenString string) (*XRHID, error)
func (v *CRCAuthValidator) ValidateJWTHeaderRequest(r *http.Request) (*XRHID, error)
func (v *CRCAuthValidator) ValidateJWTCookieRequest(r *http.Request) (*XRHID, error)
```

## Development

### Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/redhatinsights/crcauthlib.git
cd crcauthlib
go mod download
```

### Available Commands

| Command | Description |
|---------|-------------|
| `make test` | Run tests with race detector |
| `make coverage` | Generate test coverage report (coverage.out) |
| `make lint` | Run golangci-lint with 50+ linters |

### Testing

Run the test suite:

```bash
make test
```

Generate coverage report:

```bash
make coverage
```

### Linting

The project uses golangci-lint with comprehensive linter configuration:

```bash
make lint
```

### Continuous Integration

GitHub Actions automatically runs tests on:
- Go versions: 1.25, 1.26
- Platforms: Ubuntu, macOS

## Dependencies

- [github.com/golang-jwt/jwt/v4][jwt] - JWT token processing
- [github.com/redhatinsights/platform-go-middlewares/v2][middlewares] - Identity handling

## Contributing

See [CONTRIBUTING.md][contributing] for guidelines on contributing to this project.

## License

Please contact the repository maintainers for licensing information.

## Versioning

Latest version: v0.6.0

This project follows semantic versioning. See the [releases page][releases] for version history.

[jwt]: https://github.com/golang-jwt/jwt
[middlewares]: https://github.com/redhatinsights/platform-go-middlewares
[contributing]: CONTRIBUTING.md
[releases]: https://github.com/redhatinsights/crcauthlib/releases
