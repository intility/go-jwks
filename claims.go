package jwt

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Custom claims struct for easier and type safe retrieval
// of OIDC claims from context in handlers.
type UserClaims struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Username string `json:"preferred_username,omitempty"`

	jwt.RegisteredClaims
}

type contextKey string

const userClaimsKey contextKey = "userClaims"

// extracts claims data from context returned by the jwt middleware.
func ClaimsFromContext(ctx context.Context) (*UserClaims, error) {
	claimsData := ctx.Value(userClaimsKey)
	if claimsData == nil {
		return nil, fmt.Errorf("no claims in context")
	}

	claims, ok := claimsData.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("failed to assert claims data")
	}

	return claims, nil

}
