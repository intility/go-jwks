package jwt

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ValidatorConfiguration holds required validator configuration and optional claims checks
// to be carried out by the validator.
type ValidatorConfiguration struct {
	issuers      []string
	audiences    []string
	validMethods []string
	// optional user specified claim validators
	claimChecks []func(context.Context, jwt.Claims) error
}

// ValidatorOption modifies the default validator configuration and may return an error for invalid input.
type ValidatorOption func(*ValidatorConfiguration) error

// ValidatorOptions is the previous name of ValidatorConfiguration.
//
// Deprecated: Use ValidatorConfiguration instead.
type ValidatorOptions = ValidatorConfiguration

// ValidatorOptionFunc is the previous name of ValidatorOption.
//
// Deprecated: Use ValidatorOption instead.
type ValidatorOptionFunc = ValidatorOption

// WithIssuers sets any number of allowed issuers.
// Must be used for multi-tenant applications.
// Default is inferred from fetched discovery document.
func WithIssuers(issuers ...string) ValidatorOption {
	return func(o *ValidatorConfiguration) error {
		if len(issuers) == 0 {
			return fmt.Errorf("WithIssuers requires at least one issuer")
		}

		o.issuers = issuers
		return nil
	}
}

// WithAdditionalAudiences appends additional allowed audiences to the required audience.
func WithAdditionalAudiences(audiences ...string) ValidatorOption {
	return func(o *ValidatorConfiguration) error {
		if len(audiences) == 0 {
			return fmt.Errorf("WithAdditionalAudiences requires at least one audience")
		}

		o.audiences = append(o.audiences, audiences...)
		return nil
	}
}

// WithValidMethods sets all allowed signing methods.
// Default is RS256.
func WithValidMethods(methods ...string) ValidatorOption {
	return func(o *ValidatorConfiguration) error {
		if len(methods) == 0 {
			return fmt.Errorf("WithValidMethods requires at least one method")
		}

		o.validMethods = methods
		return nil
	}
}

// WithClaimValidator registers a type-safe check for claims that are not covered
// by the standard issuer, audience and expiry validation.
//
// Multiple validators run in registration order and the first error fails validation.
//
// Example custom validator:
//
//	WithClaimValidator(func(_ context.Context, c *MyClaims) error {
//		if c.Azp != expectedClientID {
//			return fmt.Errorf("azp %q not allowed", c.Azp)
//		}
//		return nil
//	})
//
// Warning: claim type is evaluated at runtime.
func WithClaimValidator[T jwt.Claims](fn func(ctx context.Context, claims T) error) ValidatorOption {
	return func(o *ValidatorConfiguration) error {
		if fn == nil {
			return fmt.Errorf("WithClaimValidator requires a non-nil function")
		}

		o.claimChecks = append(o.claimChecks, func(ctx context.Context, c jwt.Claims) error {
			typed, ok := c.(T)
			if !ok {
				return fmt.Errorf("claim validator type mismatch: got %T", c)
			}

			return fn(ctx, typed)
		})

		return nil
	}
}
