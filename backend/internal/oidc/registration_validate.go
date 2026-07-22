package oidc

import (
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

// ValidateRegistrationRedirectURIs ensures at least one redirect URI is present and
// every redirect URI matches at least one allowlist pattern. An empty allowlist denies
// all registrations (fail-closed).
func ValidateRegistrationRedirectURIs(redirectURIs []string, allowlist []string) error {
	if len(redirectURIs) == 0 {
		return &common.ValidationError{Message: "at least one redirect_uri is required"}
	}
	for _, uri := range redirectURIs {
		if !utils.MatchesAnyURLPattern(allowlist, uri) {
			return &common.ValidationError{Message: "redirect_uri '" + uri + "' is not permitted"}
		}
	}
	return nil
}
