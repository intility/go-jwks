# Go JWKS Fetcher and JWT Validator

 A Go library for JWT validation with automatic JWKS fetching and key rotation. Includes HTTP middleware.

## Features

- **Minimal Config** — Get up and running with just your audience + tenant ID or genric discovery endpoint
- **OIDC Discovery** — Fetches JWKS URI and issuer from discovery endpoints
- **HTTP Middleware** — Drop-in `http.Handler` middleware for protected routes
- **Generic OIDC** — Works with Auth0, Okta, Keycloak, or any OIDC provider 

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

The fetcher uses secure defaults (HTTPS required, TLS 1.2+, 24h refresh). Override when needed:

```go
fetcher, err := jwks.NewJWKSFetcher(
    jwks.Generic{DiscoveryURL: "https://auth.example.com/.well-known/openid-configuration"},
    jwks.WithFetchInterval(12 * time.Hour),                      // Override refresh interval (default: 24h)
    jwks.WithAllowedJWKSHosts([]string{"auth.example.com"}),     // Restrict JWKS to specific hosts
    jwks.WithMicrosoftHosts(),                                   // Preset for Microsoft Entra ID hosts
    jwks.WithRequireHTTPS(false),                                // Allow HTTP (default: true)
    jwks.WithTLSConfig(customTLSConfig),                         // Custom TLS configuration
    jwks.WithMaxResponseSize(512 * 1024),                        // Limit response size (default: 1MB)
    jwks.WithMaxKeysCount(50),                                   // Limit key count (default: 100)
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
