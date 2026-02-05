// Basic example demonstrating JWKS fetching and JWT validation middleware.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	jwks "github.com/intility/go-jwks"
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
		return
	}

	// Start fetching JWKS (performs initial fetch synchronously)
	if err := fetcher.Start(ctx); err != nil {
		slog.Error("failed to start JWKS fetcher", "error", err)
		return
	}

	// Create the JWT Validator instance
	// - audience is required (first parameter)
	// - issuer defaults to discovery document (override with WithIssuers for multi-tenant)
	// - signing methods default to RS256 (override with WithValidMethods)
	validator, err := fetcher.NewJWTValidator("api://YOUR_API_CLIENT_ID")
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
	// Access default UserClaims from context
	claims, err := jwks.ClaimsFromContext[*jwks.UserClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get claims", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"message": "pong", "user": "%s"}`, claims.Email)
}
