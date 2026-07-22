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

		// Synthesized DCR response metadata: derived from the stored model,
		// not persisted verbatim from the request.
		assert.Equal(t, "client_secret_basic", doc.TokenEndpointAuthMethod)
		assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Contains(t, doc.ResponseTypes, "code")
		assert.Equal(t, []string{"https://app.example.com/cb"}, doc.RedirectURIs)
	})

	t.Run("registers a public client with token_endpoint_auth_method none", func(t *testing.T) {
		body := `{"redirect_uris":["https://app.example.com/cb"],"client_name":"Public","token_endpoint_auth_method":"none"}`
		resp := post(t, "/api/oidc/register", body)
		require.Equal(t, http.StatusCreated, resp.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
		assert.Equal(t, "none", doc.TokenEndpointAuthMethod)
		assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Contains(t, doc.ResponseTypes, "code")
	})

	t.Run("logo_uri pointing at a private/loopback address does not fail registration", func(t *testing.T) {
		body := `{"redirect_uris":["https://app.example.com/cb"],"client_name":"C","token_endpoint_auth_method":"client_secret_basic","logo_uri":"http://127.0.0.1/logo.png"}`
		resp := post(t, "/api/oidc/register", body)
		require.Equal(t, http.StatusCreated, resp.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
		assert.NotEmpty(t, doc.ClientID)
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

// TestRegistrationClientConfigurationEndpoint exercises the RFC 7592 client
// configuration endpoints (GET/PUT/DELETE /api/oidc/register/:id) at the HTTP
// layer, including the status-code regressions from the final review: a PUT
// with an out-of-allowlist redirect URI must return 400 (not 401), and a PUT
// that moves a public client to a confidential auth method must return a
// non-empty client_secret.
func TestRegistrationClientConfigurationEndpoint(t *testing.T) {
	original := common.EnvConfig
	t.Cleanup(func() { common.EnvConfig = original })
	common.EnvConfig.UiConfigDisabled = true
	common.EnvConfig.DCREnabled = true

	router := newTestRegistrationRouter(t)

	do := func(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		var reader *strings.Reader
		if body != "" {
			reader = strings.NewReader(body)
		} else {
			reader = strings.NewReader("")
		}
		req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	register := func(t *testing.T, body string) dto.OidcClientRegistrationResponseDto {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oidc/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
		return doc
	}

	// Register a confidential client for GET/PUT/DELETE happy-path assertions.
	confidential := register(t, `{"redirect_uris":["https://app.example.com/cb"],"client_name":"C","token_endpoint_auth_method":"client_secret_basic"}`)
	path := "/api/oidc/register/" + confidential.ClientID

	t.Run("GET with a valid bearer token returns the client", func(t *testing.T) {
		resp := do(t, http.MethodGet, path, confidential.RegistrationAccessToken, "")
		require.Equal(t, http.StatusOK, resp.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
		assert.Equal(t, confidential.ClientID, doc.ClientID)

		// Synthesized DCR response metadata, consistent with the register response.
		assert.Equal(t, "client_secret_basic", doc.TokenEndpointAuthMethod)
		assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Contains(t, doc.ResponseTypes, "code")
		assert.Equal(t, []string{"https://app.example.com/cb"}, doc.RedirectURIs)
	})

	t.Run("GET with a wrong bearer token returns 401", func(t *testing.T) {
		resp := do(t, http.MethodGet, path, "wrong-token", "")
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("GET with no bearer token returns 401", func(t *testing.T) {
		resp := do(t, http.MethodGet, path, "", "")
		require.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("PUT with a redirect URI outside the allowlist returns 400", func(t *testing.T) {
		resp := do(t, http.MethodPut, path, confidential.RegistrationAccessToken,
			`{"redirect_uris":["https://evil.example.com/cb"],"client_name":"C","token_endpoint_auth_method":"client_secret_basic"}`)
		require.Equal(t, http.StatusBadRequest, resp.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
		assert.Equal(t, "invalid_redirect_uri", body["error"])
	})

	t.Run("PUT switching a public client to client_secret_basic returns a new client_secret", func(t *testing.T) {
		public := register(t, `{"redirect_uris":["https://app.example.com/cb"],"client_name":"Public","token_endpoint_auth_method":"none"}`)
		require.Empty(t, public.ClientSecret)
		assert.Equal(t, "none", public.TokenEndpointAuthMethod)

		publicPath := "/api/oidc/register/" + public.ClientID
		resp := do(t, http.MethodPut, publicPath, public.RegistrationAccessToken,
			`{"redirect_uris":["https://app.example.com/cb"],"client_name":"Public","token_endpoint_auth_method":"client_secret_basic"}`)
		require.Equal(t, http.StatusOK, resp.Code)
		var doc dto.OidcClientRegistrationResponseDto
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &doc))
		assert.NotEmpty(t, doc.ClientSecret)

		// Synthesized DCR response metadata reflects the post-update state
		// (now confidential), consistent with register/GET.
		assert.Equal(t, "client_secret_basic", doc.TokenEndpointAuthMethod)
		assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Contains(t, doc.ResponseTypes, "code")
		assert.Equal(t, []string{"https://app.example.com/cb"}, doc.RedirectURIs)
	})

	t.Run("DELETE with a valid token removes the client, subsequent GET returns 401", func(t *testing.T) {
		resp := do(t, http.MethodDelete, path, confidential.RegistrationAccessToken, "")
		require.Equal(t, http.StatusNoContent, resp.Code)

		getResp := do(t, http.MethodGet, path, confidential.RegistrationAccessToken, "")
		require.Equal(t, http.StatusUnauthorized, getResp.Code)
	})
}
