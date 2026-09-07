package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// azpClaims exercises WithClaimValidator against a non-standard claim.
type azpClaims struct {
	Azp string `json:"azp,omitempty"`
	jwtpkg.RegisteredClaims
}

const (
	claimTestKid      = "claim-test-kid"
	claimTestAudience = "api://claim-test"
	claimTestIssuer   = "https://claims.example.com"
)

// newClaimTestFetcher returns a fetcher with a static JWKS plus the private key
// backing it, so tests can mint tokens the validator accepts.
func newClaimTestFetcher(t *testing.T) (*JWKSFetcher, *rsa.PrivateKey) {
	t.Helper()

	signingKey, err := generateRSAKey()
	require.NoError(t, err)

	nBase64URL := base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes())
	eBase64URL := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.E)).Bytes())

	fetcher := &JWKSFetcher{
		jwks: &JWKS{
			Keys: []JSONWebKey{{
				Kid: claimTestKid,
				Kty: keyTypeRSA,
				N:   nBase64URL,
				E:   eBase64URL,
			}},
		},
		mutex:  &sync.RWMutex{},
		logger: slog.Default().With("pkg", "jwks"),
	}

	return fetcher, signingKey
}

// mintToken signs a token carrying the given azp and expiry.
func mintToken(t *testing.T, signingKey *rsa.PrivateKey, azp string, expiry time.Time) string {
	t.Helper()

	token := jwtpkg.New(jwtpkg.SigningMethodRS256)
	token.Header["kid"] = claimTestKid
	claims := token.Claims.(jwtpkg.MapClaims)
	claims["aud"] = claimTestAudience
	claims["iss"] = claimTestIssuer
	claims["exp"] = expiry.Unix()
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	if azp != "" {
		claims["azp"] = azp
	}

	tokenStr, err := token.SignedString(signingKey)
	require.NoError(t, err)

	return tokenStr
}

func requireAzp(allowed ...string) func(context.Context, *azpClaims) error {
	return func(_ context.Context, c *azpClaims) error {
		if !slices.Contains(allowed, c.Azp) {
			return fmt.Errorf("azp %q not allowed", c.Azp)
		}
		return nil
	}
}

func newAzpValidator(t *testing.T, fetcher *JWKSFetcher, options ...ValidatorOptionFunc) *JWTValidator[*azpClaims] {
	t.Helper()

	v, err := NewJWTValidatorWithClaims(
		fetcher,
		claimTestAudience,
		func() *azpClaims { return &azpClaims{} },
		append([]ValidatorOptionFunc{WithIssuers(claimTestIssuer)}, options...)...,
	)
	require.NoError(t, err)

	return v
}

func TestWithClaimValidator(t *testing.T) {
	fetcher, signer := newClaimTestFetcher(t)
	validExpiry := time.Now().Add(time.Hour)

	t.Run("accepts token when check passes", func(t *testing.T) {
		v := newAzpValidator(t, fetcher, WithClaimValidator(requireAzp("client-a", "client-b")))

		claims, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "client-b", validExpiry))
		assert.NoError(t, err)
		assert.Equal(t, "client-b", claims.Azp)
	})

	t.Run("rejects token when check fails", func(t *testing.T) {
		v := newAzpValidator(t, fetcher, WithClaimValidator(requireAzp("client-a")))

		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "attacker", validExpiry))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClaim, "failure should wrap ErrInvalidClaim")
		assert.Contains(t, err.Error(), `azp "attacker" not allowed`, "user error should be wrapped, not discarded")
	})

	t.Run("rejects token when claim is absent", func(t *testing.T) {
		v := newAzpValidator(t, fetcher, WithClaimValidator(requireAzp("client-a")))

		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "", validExpiry))
		assert.ErrorIs(t, err, ErrInvalidClaim)
	})

	t.Run("runs multiple validators in order and stops at first error", func(t *testing.T) {
		var order []string

		first := func(_ context.Context, _ *azpClaims) error {
			order = append(order, "first")
			return nil
		}
		second := func(_ context.Context, _ *azpClaims) error {
			order = append(order, "second")
			return errors.New("second failed")
		}
		third := func(_ context.Context, _ *azpClaims) error {
			order = append(order, "third")
			return nil
		}

		v := newAzpValidator(t, fetcher,
			WithClaimValidator(first),
			WithClaimValidator(second),
			WithClaimValidator(third),
		)

		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "client-a", validExpiry))
		assert.ErrorIs(t, err, ErrInvalidClaim)
		assert.Equal(t, []string{"first", "second"}, order, "third must not run after second fails")
	})

	t.Run("receives the request context", func(t *testing.T) {
		type ctxKey string
		const key ctxKey = "trace-id"

		var seen any
		v := newAzpValidator(t, fetcher, WithClaimValidator(func(ctx context.Context, _ *azpClaims) error {
			seen = ctx.Value(key)
			return nil
		}))

		ctx := context.WithValue(context.Background(), key, "abc123")
		_, err := v.ValidateJWT(ctx, mintToken(t, signer, "client-a", validExpiry))
		assert.NoError(t, err)
		assert.Equal(t, "abc123", seen, "ctx should be threaded through to the check")
	})

	t.Run("does not run when standard validation fails", func(t *testing.T) {
		called := false
		v := newAzpValidator(t, fetcher, WithClaimValidator(func(_ context.Context, _ *azpClaims) error {
			called = true
			return nil
		}))

		// Expired token: parsing fails before any claim check should run.
		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "client-a", time.Now().Add(-time.Hour)))
		require.Error(t, err)
		assert.False(t, called, "check must not see a token that failed standard validation")
	})

	t.Run("rejects a nil function at construction", func(t *testing.T) {
		_, err := NewJWTValidatorWithClaims(
			fetcher,
			claimTestAudience,
			func() *azpClaims { return &azpClaims{} },
			WithIssuers(claimTestIssuer),
			WithClaimValidator[*azpClaims](nil),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-nil function")
	})

	t.Run("reports a claims type mismatch at validation time", func(t *testing.T) {
		// Validator produces *azpClaims but the check expects *UserClaims.
		v := newAzpValidator(t, fetcher, WithClaimValidator(func(_ context.Context, _ *UserClaims) error {
			return nil
		}))

		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "client-a", validExpiry))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClaim)
		assert.Contains(t, err.Error(), "type mismatch")
	})

	t.Run("validator without checks is unaffected", func(t *testing.T) {
		v := newAzpValidator(t, fetcher)

		_, err := v.ValidateJWT(context.Background(), mintToken(t, signer, "anything", validExpiry))
		assert.NoError(t, err)
	})
}
