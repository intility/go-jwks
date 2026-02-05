// Custom claims example demonstrating how to use generic claims types
// for parsing application-specific JWT claims.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	jwks "github.com/intility/go-jwks"
)

// MyClaims defines custom claims for your application.
// Embed jwt.RegisteredClaims to get standard fields (iss, aud, exp, etc.)
type MyClaims struct {
	TenantID   string   `json:"tenant_id"`
	Roles      []string `json:"roles"`
	Department string   `json:"department,omitempty"`

	jwt.RegisteredClaims
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fetcher, err := jwks.NewJWKSFetcher(jwks.EntraID{TenantID: "your-tenant-id"})
	if err != nil {
		slog.Error("failed to create fetcher", "error", err)
		return
	}

	if err := fetcher.Start(ctx); err != nil {
		slog.Error("failed to start JWKS fetcher", "error", err)
		return
	}

	// Use NewJWTValidatorWithClaims to specify your custom claims type.
	// The factory function must return a pointer type for JSON decoding.
	// - audience is required (second parameter)
	// - issuer defaults to discovery document (override with WithIssuers for multi-tenant)
	// - signing methods default to RS256 (override with WithValidMethods)
	validator, err := jwks.NewJWTValidatorWithClaims(
		fetcher,
		"api://YOUR_API_CLIENT_ID",
		func() *MyClaims { return &MyClaims{} },
	)
	if err != nil {
		slog.Error("failed to create JWT validator", "error", err)
		return
	}

	jwtMiddleware := jwks.JWTMiddleware(validator)

	mux := http.NewServeMux()
	mux.Handle("/api/protected/profile", jwtMiddleware(http.HandlerFunc(profileHandler)))

	slog.Info("Server starting on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("Server failed", "error", err)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Extract your custom claims type from context using the generic function.
	// The type parameter must match what you used with NewJWTValidatorWithClaims.
	claims, err := jwks.ClaimsFromContext[*MyClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get claims", http.StatusUnauthorized)
		return
	}

	// Access custom fields with full type safety
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"tenant": "%s", "roles": %q, "department": "%s"}`,
		claims.TenantID,
		claims.Roles,
		claims.Department,
	)
}
