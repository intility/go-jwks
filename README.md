# Go JWKS Fetcher and JWT Validator

A go package for fetching JSON Web Key Sets (JWKS) and validating 
JSON Web Tokens (JWTs) using these keys. It includes HTTP middleware for integration 
with web services.

## Features
*   **JWKS Fetching:** Retrieves JWKS from a specified discovery URL (e.g. Microsoft Entra ID discovery endpoint).
*   **Automatic Key Rotation:** Periodically fetches the JWKS endpoint to ensure keys are up-to-date.
*   **JWT Validation:**
    *   Verifies the JWT signature using the public key corresponding to the `kid` (Key ID) in the token header.
    *   Validates the `alg` (algorithm) used for signing against a configurable list.
    *   Validates the `aud` (audience) claim against a configurable list of allowed audiences.
    *   Validates the `iss` (issuer) against the configured issuer. 
*   **HTTP Middleware:** Provides standard Go `http.Handler` middleware to protect endpoints.
*   **Standalone JWT validator:** Validate any JWT directly.
*   **RSA Support:** Currently supports JWTs signed with RSA algorithms. 

## Installation
```bash
go get github.com/intility/go-jwks
```


## Quick Start
```go
fetcher, _ := jwks.NewJWKSFetcher(jwks.EntraID{TenantID: "your-tenant-id"})
fetcher.Start(ctx)

validator, _ := fetcher.NewJWTValidator("api://your-audience")
middleware := jwks.JWTMiddleware(validator)

mux.Handle("/protected", middleware(yourHandler))
```

The validator uses **smart defaults**:
- **Issuer**: Automatically extracted from the OIDC discovery document
- **Signing methods**: RS256 (the most common algorithm)

See the [examples](./examples) folder for complete runnable examples:
- **[basic](./examples/basic)** - Standard JWT validation with HTTP middleware
- **[custom-claims](./examples/custom-claims)** - Using generic claims types for application-specific JWT fields

## Fetcher Options

The `JWKSFetcher` can be configured using functional options to customize its behavior:

### Security Options
- `WithRequireHTTPS(bool)` - Enforce HTTPS for JWKS endpoints (default: true)
- `WithAllowedJWKSHosts([]string)` - Restrict JWKS fetching to specific hosts
- `WithMicrosoftHosts()` - Preset configuration for Microsoft Entra ID hosts
- `WithTLSConfig(*tls.Config)` - Custom TLS configuration for JWKS requests

### Performance Options
- `WithFetchInterval(time.Duration)` - Set the interval for refreshing JWKS (default: 24 hours)
- `WithMaxResponseSize(int64)` - Limit JWKS response size (default: 1MB)
- `WithMaxKeysCount(int)` - Limit the number of keys in JWKS (default: 100)

### Example with Options
```go
fetcher, err := jwks.NewJWKSFetcher(
    jwks.Generic{DiscoveryURL: "https://auth.example.com/.well-known/openid-configuration"},
    jwks.WithFetchInterval(12 * time.Hour),
    jwks.WithAllowedJWKSHosts([]string{"auth.example.com"}),
    jwks.WithMaxKeysCount(50),
)
```

## Validator Options

The validator uses smart defaults (issuer from discovery, RS256 signing). Override when needed:

```go
validator, err := fetcher.NewJWTValidator("api://my-app",
    jwks.WithIssuers("https://custom-issuer"),       // Override discovery issuer
    jwks.WithAdditionalAudiences("api://other"),    // Add more audiences
    jwks.WithValidMethods("RS384"),                 // Override signing methods
)
```

## Security Features

This library implements several security best practices by default:


### Host Allowlisting
Protect against SSRF attacks by restricting which hosts can serve JWKS:
```go
fetcher, err := jwks.NewJWKSFetcher(
    jwks.Generic{DiscoveryURL: "https://auth.example.com/.well-known/openid-configuration"},
    jwks.WithAllowedJWKSHosts([]string{"auth.example.com", "backup-auth.example.com"}),
)
```

For Microsoft Entra ID, use the preset configuration:
```go
fetcher, err := jwks.NewJWKSFetcher(
    jwks.EntraID{TenantID: "your-tenant-id"},
    jwks.WithMicrosoftHosts(), // Allows only Microsoft's auth domains
)
```

### Secure Defaults
- **HTTPS Required**: By default, only HTTPS URLs are accepted for JWKS endpoints. This can be disabled for testing/internal environments using `WithRequireHTTPS(false)`
- **TLS 1.2+**: Minimum TLS version 1.2 is enforced for all HTTPS connections
- **Response Size Limits**: JWKS responses are limited to 1MB by default to prevent memory exhaustion attacks
- **Key Count Limits**: Maximum of 100 keys per JWKS to prevent resource exhaustion


## How It Works

1. **Fetcher** retrieves public keys from the OIDC discovery endpoint and refreshes them periodically (default: 24h)
2. **Validator** uses these keys to verify JWT signatures and validate claims (issuer, audience, expiry)
3. **Middleware** extracts the Bearer token from `Authorization` header and validates it

## Standalone Validation

For validating JWTs outside of HTTP handlers:

```go
claims, err := validator.ValidateJWT(ctx, tokenString)
if err != nil {
    if errors.Is(err, jwks.ErrInvalidAud) {
        // Handle invalid audience
    }
    return err
}
fmt.Printf("User: %s\n", claims.Email)
```

**Error types:** `ErrInvalidToken`, `ErrInvalidAud`, `ErrInvalidIss`
