//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

func TestRegisterDynamicClient(t *testing.T) {
	// GetDynamicClientRedirectUriAllowlist and GetDynamicClientRetention read from the
	// in-memory env config, which GetConfig only returns when the UI config is disabled.
	original := common.EnvConfig
	t.Cleanup(func() { common.EnvConfig = original })
	common.EnvConfig.UiConfigDisabled = true

	db := testutils.NewDatabaseForTest(t)

	cfg := appconfig.NewTestConfig(nil)
	cfg.DynamicClientRedirectUriAllowlist = appconfig.AppConfigValue(`["https://app.example.com/**"]`)
	cfg.DynamicClientRetentionDays = appconfig.AppConfigValue("180")
	appConfigService := appconfig.NewTestAppConfigService(cfg)

	svc, err := NewOidcService(db, nil, nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	svc.appConfigService = appConfigService

	t.Run("confidential client gets a secret and a registration token", func(t *testing.T) {
		client, secret, regToken, err := svc.RegisterDynamicClient(t.Context(), dto.OidcClientRegistrationRequestDto{
			RedirectURIs:            []string{"https://app.example.com/cb"},
			ClientName:              "MCP Client",
			TokenEndpointAuthMethod: "client_secret_basic",
		})
		require.NoError(t, err)
		assert.Equal(t, model.OidcClientTypeDynamic, client.ClientType)
		assert.NotEmpty(t, secret)
		assert.NotEmpty(t, regToken)
		assert.NotNil(t, client.RegistrationAccessTokenHash)
		assert.NotNil(t, client.MetadataExpiresAt) // freshness set to now+retention
	})

	t.Run("public client (auth method none) gets no secret", func(t *testing.T) {
		client, secret, _, err := svc.RegisterDynamicClient(t.Context(), dto.OidcClientRegistrationRequestDto{
			RedirectURIs:            []string{"https://app.example.com/cb"},
			TokenEndpointAuthMethod: "none",
		})
		require.NoError(t, err)
		assert.True(t, client.IsPublic)
		assert.Empty(t, secret)
	})

	t.Run("redirect URI outside the allowlist is rejected", func(t *testing.T) {
		_, _, _, err := svc.RegisterDynamicClient(t.Context(), dto.OidcClientRegistrationRequestDto{
			RedirectURIs: []string{"https://evil.example.com/cb"},
		})
		require.Error(t, err)
	})
}
