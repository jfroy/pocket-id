//go:build unit

package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

func newTestRegistrationRouter(t *testing.T) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	db := testutils.NewDatabaseForTest(t)

	cfg := appconfig.NewTestConfig(nil)
	cfg.DynamicClientRedirectUriAllowlist = appconfig.AppConfigValue(`["https://app.example.com/**"]`)
	appConfigService := appconfig.NewTestAppConfigService(cfg)

	svc, err := service.NewOidcService(db, nil, appConfigService, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	router := gin.New()
	group := router.Group("/api")
	NewOidcRegistrationController(group, svc)
	return router
}

func TestRegistrationEndpoint(t *testing.T) {
	original := common.EnvConfig
	t.Cleanup(func() { common.EnvConfig = original })
	common.EnvConfig.UiConfigDisabled = true
	common.EnvConfig.DCREnabled = true

	router := newTestRegistrationRouter(t)

	post := func(t *testing.T, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("registers a client when DCR is enabled", func(t *testing.T) {
		body := `{"redirect_uris":["https://app.example.com/cb"],"client_name":"C","token_endpoint_auth_method":"client_secret_basic"}`
		resp := post(t, "/api/oidc/register", body)
		require.Equal(t, http.StatusCreated, resp.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
		assert.NotEmpty(t, doc.ClientID)
		assert.NotEmpty(t, doc.ClientSecret)
		assert.NotEmpty(t, doc.RegistrationAccessToken)
		assert.Contains(t, doc.RegistrationClientURI, doc.ClientID)
	})

	t.Run("returns 403 when DCR is disabled", func(t *testing.T) {
		common.EnvConfig.DCREnabled = false
		defer func() { common.EnvConfig.DCREnabled = true }()
		resp := post(t, "/api/oidc/register", `{"redirect_uris":["https://app.example.com/cb"]}`)
		require.Equal(t, http.StatusForbidden, resp.Code)
	})

	t.Run("rejects a redirect URI outside the allowlist", func(t *testing.T) {
		resp := post(t, "/api/oidc/register", `{"redirect_uris":["https://evil.example.com/cb"]}`)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})
}
