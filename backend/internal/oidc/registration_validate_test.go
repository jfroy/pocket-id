package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRegistrationRedirectURIs(t *testing.T) {
	allow := []string{"https://app.example.com/**"}

	require.NoError(t, ValidateRegistrationRedirectURIs([]string{"https://app.example.com/cb"}, allow))

	// No redirect URIs is invalid.
	require.Error(t, ValidateRegistrationRedirectURIs(nil, allow))

	// A URI outside the allowlist is rejected.
	require.Error(t, ValidateRegistrationRedirectURIs([]string{"https://evil.example.com/cb"}, allow))

	// An empty allowlist denies everything (fail-closed).
	require.Error(t, ValidateRegistrationRedirectURIs([]string{"https://app.example.com/cb"}, nil))
}
