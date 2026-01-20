package jwt

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Default custom claims struct for easier and type safe retrieval
// of OIDC claims from context in handlers.
type UserClaims struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Username string `json:"preferred_username,omitempty"`

	jwt.RegisteredClaims
}

type contextKey string

const userClaimsKey contextKey = "userClaims"

// Helper to extract claims data from context returned by the jwt middleware.
func ClaimsFromContext[T jwt.Claims](ctx context.Context) (T, error) {
	var zero T
	claimsData := ctx.Value(userClaimsKey)
	if claimsData == nil {
		return zero, fmt.Errorf("no claims in context")
	}

	claims, ok := claimsData.(T)
	if !ok {
		return zero, fmt.Errorf("failed to assert claims data")
	}

	return claims, nil
}
