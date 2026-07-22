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

func TestDynamicClientConfiguration(t *testing.T) {
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

	// Register a confidential dynamic client, capturing clientID + regToken.
	registered, _, regToken, err := svc.RegisterDynamicClient(t.Context(), dto.OidcClientRegistrationRequestDto{
		RedirectURIs:            []string{"https://app.example.com/cb"},
		ClientName:              "MCP Client",
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	require.NoError(t, err)
	clientID := registered.ID

	// Create a standard (non-dynamic) client directly in the DB.
	standardClient := model.OidcClient{
		Name:         "Standard Client",
		CallbackURLs: model.UrlList{"https://app.example.com/cb"},
		ClientType:   model.OidcClientTypeStandard,
	}
	require.NoError(t, db.Create(&standardClient).Error)
	standardID := standardClient.ID

	t.Run("GET returns the client with a valid token", func(t *testing.T) {
		got, err := svc.GetDynamicClient(t.Context(), clientID, regToken)
		require.NoError(t, err)
		assert.Equal(t, clientID, got.ID)
	})

	t.Run("GET with a wrong token is rejected", func(t *testing.T) {
		_, err := svc.GetDynamicClient(t.Context(), clientID, "wrong-token")
		require.Error(t, err)
	})

	t.Run("GET on a non-dynamic client is rejected", func(t *testing.T) {
		_, err := svc.GetDynamicClient(t.Context(), standardID, regToken)
		require.Error(t, err)
	})

	t.Run("PUT updates and re-validates redirect URIs", func(t *testing.T) {
		updated, err := svc.UpdateDynamicClient(t.Context(), clientID, regToken, dto.OidcClientRegistrationRequestDto{
			RedirectURIs: []string{"https://app.example.com/new"},
			ClientName:   "Renamed",
		})
		require.NoError(t, err)
		assert.Equal(t, "Renamed", updated.Name)
	})

	t.Run("PUT rejects a redirect URI outside the allowlist", func(t *testing.T) {
		_, err := svc.UpdateDynamicClient(t.Context(), clientID, regToken, dto.OidcClientRegistrationRequestDto{
			RedirectURIs: []string{"https://evil.example.com/cb"},
		})
		require.Error(t, err)
	})

	t.Run("DELETE removes the client", func(t *testing.T) {
		require.NoError(t, svc.DeleteDynamicClient(t.Context(), clientID, regToken))
		_, err := svc.GetDynamicClient(t.Context(), clientID, regToken)
		require.Error(t, err)
	})
}
