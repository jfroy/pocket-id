package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	jwkutils "github.com/pocket-id/pocket-id/backend/internal/utils/jwk"
)

func newMinimalJwtService(t *testing.T) *service.JwtService {
	t.Helper()

	key, err := jwkutils.GenerateKey(jwa.RS256().String(), "")
	require.NoError(t, err, "failed to generate test JWK key")

	svc := &service.JwtService{}
	require.NoError(t, svc.SetKey(key), "failed to set JWK key on JwtService")
	return svc
}

func TestClientIDMetadataDocumentDiscoveryFlag(t *testing.T) {
	origFlag := common.EnvConfig.CIMDEnabled
	origURL := common.EnvConfig.AppURL
	t.Cleanup(func() {
		common.EnvConfig.CIMDEnabled = origFlag
		common.EnvConfig.AppURL = origURL
	})

	common.EnvConfig.AppURL = "https://test.example.com"
	jwtSvc := newMinimalJwtService(t)

	parse := func(t *testing.T) map[string]any {
		t.Helper()
		wkc := &WellKnownController{jwtService: jwtSvc}
		raw, err := wkc.computeOIDCConfiguration()
		require.NoError(t, err)
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(raw, &cfg))
		return cfg
	}

	common.EnvConfig.CIMDEnabled = true
	assert.Equal(t, true, parse(t)["client_id_metadata_document_supported"])

	common.EnvConfig.CIMDEnabled = false
	assert.Equal(t, false, parse(t)["client_id_metadata_document_supported"])
}

func TestOAuthAuthorizationServerMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	jwtSvc := newMinimalJwtService(t)

	router := gin.New()
	group := router.Group("/")
	NewWellKnownController(group, jwtSvc)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-authorization-server", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	assert.Equal(t, common.EnvConfig.AppURL, doc["issuer"])
	assert.Equal(t, common.EnvConfig.AppURL+"/authorize", doc["authorization_endpoint"])
	assert.NotEmpty(t, doc["jwks_uri"])
	assert.Contains(t, doc["code_challenge_methods_supported"], "S256")
	assert.Equal(t, true, doc["resource_indicators_supported"])
	assert.NotEmpty(t, doc["registration_endpoint"]) // always advertised (Phase 3 makes it functional)
}
