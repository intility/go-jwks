# Go JWKS Fetcher and JWT Validator

A go package for fetching JSON Web Key Sets (JWKS) from an authorization server
and validating JSON Web Tokens (JWTs) using these keys. It includes HTTP middleware for integration 
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


## Example
```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	jwks "github.com/intility/go-jwks"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() 

	// The NewJWKSFetcher takes a keysource to fetch public keys.
	// The keySource interface is satisfied by EntraID and Generic.
	// Optionally set other parameters using functional options.
	fetcher, err := jwks.NewJWKSFetcher(jwks.EntraID{TenantID: "your-tenant-id"})
	if err != nil {
		slog.Error("failed to create fetcher", "error", err)
	}

  // Start fetching JWKS (performs initial fetch synchronously)
	if err := fetcher.Start(ctx); err != nil {
		slog.Error("failed to start JWKS fetcher", "error", err)
		return
	}

	// Configure JWT Validator
	audiences := []string{"api://YOUR_API_CLIENT_ID"}

	// Specify allowed signing algorithms
	validMethods := []string{jwt.SigningMethodRS256.Alg()}

	// Specify you issuer
	issuer := "https://auth.example.com"

	// Create the JWT Validator instance
	validator, err := jwks.NewJWTValidator(fetcher, issuer, audiences, validMethods)
	if err != nil {
		slog.Error("failed to create JWT validator", "error", err)
		return
	}

	// Create the HTTP Middleware
	jwtMiddleware := jwks.JWTMiddleware(validator)

	mux := http.NewServeMux()

	// Apply the middleware to protected routes
	mux.Handle("/api/protected/ping", jwtMiddleware(http.HandlerFunc(pingHandler)))

	slog.Info("Server starting on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("Server failed", "error", err)
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "pong"}`)
}
```

## Configuration Options

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

## Security Features

This library implements several security best practices by default:

### Secure Defaults
- **HTTPS Required**: By default, only HTTPS URLs are accepted for JWKS endpoints. This can be disabled for testing/internal environments using `WithRequireHTTPS(false)`
- **TLS 1.2+**: Minimum TLS version 1.2 is enforced for all HTTPS connections
- **Response Size Limits**: JWKS responses are limited to 1MB by default to prevent memory exhaustion attacks
- **Key Count Limits**: Maximum of 100 keys per JWKS to prevent resource exhaustion

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

### Key Usage Validation
The library validates the `use` claim in JWT keys according to RFC 7517:
- Keys marked with `use: "enc"` (encryption) are rejected for signature verification
- Only keys with `use: "sig"` or no `use` field are accepted for JWT validation
- This prevents misuse of encryption keys for signing operations

## Key fetching/synchronization
In the oauth2 protocol, the client will receive an access token signed
by an authorization server. This token can then be included in the request header sent to the server.
When the server receives this request, it needs to verify its signature using the public key from the authorization server.
These keys are rotated often, and such the server must reach out the authorization server
periodically to refresh its local key store. This synchronization is handled by the JWTFetcher running in the background.

<img src="docs/jwks-go.png" alt="flow" width="500">

## JWT validation
To start validating JWTs, create a JWTValidator instance with the NewJWTValidator function.
This object holds the in-memory store of JWKS from the fetcher, allowed audiences and valid signing methods specified by the user.

Passing this validator to the JWTMiddleware function returns a http.HandlerFunc middleware ready to authenticate incoming requests.
The middleware expects a "Authorization: Bearer \<token>" jwt header.

## Standalone validation
If validating JWTs not part of HTTP headers, the core validation function used in the middleware comes in handy.
The `ValidateJWT()` function is exported through the `JWTValidator` struct and offers standalone validation.

```go
// Validate a JWT from any source (not just HTTP headers)
claims, err := validator.ValidateJWT(ctx, tokenString)
if err != nil {
    // Check for specific error types
    if errors.Is(err, jwks.ErrInvalidAud) {
        log.Println("token has invalid audience")
    }
    log.Printf("validation failed: %v", err)
    return
}

// Access validated claims
fmt.Printf("User: %s, Email: %s\n", claims.Subject, claims.Email)
```

The function returns `ErrInvalidAud` when audience validation fails, allowing for specific error handling with `errors.Is()`.

## TODO
Add support for EC (Elliptic Curve) key types (kty: "EC") and algorithms.

