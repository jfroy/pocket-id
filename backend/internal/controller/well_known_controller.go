package controller

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/service"
)

// NewWellKnownController creates a new controller for OIDC discovery endpoints
// @Summary OIDC Discovery controller
// @Description Initializes OIDC discovery and JWKS endpoints
// @Tags Well Known
func NewWellKnownController(group *gin.RouterGroup, jwtService *service.JwtService) {
	wkc := &WellKnownController{jwtService: jwtService}

	// Pre-compute the OIDC configuration document, which is static
	var err error
	wkc.oidcConfig, err = wkc.computeOIDCConfiguration()
	if err != nil {
		slog.Error("Failed to pre-compute OpenID Connect configuration document", slog.Any("error", err))
		os.Exit(1)
		return
	}

	// Pre-compute the OAuth Authorization Server metadata document, which is static
	wkc.oauthASConfig, err = wkc.computeOAuthASMetadata()
	if err != nil {
		slog.Error("Failed to pre-compute OAuth Authorization Server metadata document", slog.Any("error", err))
		os.Exit(1)
		return
	}

	group.GET("/.well-known/jwks.json", wkc.jwksHandler)
	group.GET("/.well-known/openid-configuration", wkc.openIDConfigurationHandler)
	group.GET("/.well-known/oauth-authorization-server", wkc.oauthAuthorizationServerHandler)
}

type WellKnownController struct {
	jwtService    *service.JwtService
	oidcConfig    []byte
	oauthASConfig []byte
}

// jwksHandler godoc
// @Summary Get JSON Web Key Set (JWKS)
// @Description Returns the JSON Web Key Set used for token verification
// @Tags Well Known
// @Produce json
// @Success 200 {object} object "{ \"keys\": []interface{} }"
// @Router /.well-known/jwks.json [get]
func (wkc *WellKnownController) jwksHandler(c *gin.Context) {
	jwks, err := wkc.jwtService.GetPublicJWKSAsJSON()
	if err != nil {
		_ = c.Error(err)
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", jwks)
}

// openIDConfigurationHandler godoc
// @Summary Get OpenID Connect discovery configuration
// @Description Returns the OpenID Connect discovery document with endpoints and capabilities
// @Tags Well Known
// @Success 200 {object} object "OpenID Connect configuration"
// @Router /.well-known/openid-configuration [get]
func (wkc *WellKnownController) openIDConfigurationHandler(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", wkc.oidcConfig)
}

// oauthAuthorizationServerHandler godoc
// @Summary Get OAuth 2.0 Authorization Server metadata
// @Description Returns the RFC 8414 OAuth 2.0 Authorization Server metadata document with endpoints and capabilities
// @Tags Well Known
// @Success 200 {object} object "OAuth 2.0 Authorization Server metadata"
// @Router /.well-known/oauth-authorization-server [get]
func (wkc *WellKnownController) oauthAuthorizationServerHandler(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", wkc.oauthASConfig)
}

// computeBaseMetadata returns the set of metadata fields shared between the OpenID Connect
// discovery document and the RFC 8414 OAuth 2.0 Authorization Server metadata document.
func (wkc *WellKnownController) computeBaseMetadata() (map[string]any, error) {
	appUrl := common.EnvConfig.AppURL
	internalAppUrl := common.EnvConfig.InternalAppURL

	alg, err := wkc.jwtService.GetKeyAlg()
	if err != nil {
		return nil, fmt.Errorf("failed to get key algorithm: %w", err)
	}

	return map[string]any{
		"issuer":                                         appUrl,
		"authorization_endpoint":                         appUrl + "/authorize",
		"token_endpoint":                                 internalAppUrl + "/api/oidc/token",
		"introspection_endpoint":                         internalAppUrl + "/api/oidc/introspect",
		"device_authorization_endpoint":                  appUrl + "/api/oidc/device/authorize",
		"jwks_uri":                                       internalAppUrl + "/.well-known/jwks.json",
		"registration_endpoint":                          appUrl + "/api/oidc/register",
		"grant_types_supported":                          []string{service.GrantTypeAuthorizationCode, service.GrantTypeRefreshToken, service.GrantTypeDeviceCode, service.GrantTypeClientCredentials},
		"scopes_supported":                               []string{"openid", "profile", "email", "groups", "offline_access"},
		"response_types_supported":                       []string{"code", "id_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{alg.String()},
		"authorization_response_iss_parameter_supported": true,
		"code_challenge_methods_supported":               []string{"plain", "S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"pushed_authorization_request_endpoint":          internalAppUrl + "/api/oidc/par",
		"require_pushed_authorization_requests":          false,
		"resource_indicators_supported":                  true,
	}, nil
}

func (wkc *WellKnownController) computeOIDCConfiguration() ([]byte, error) {
	config, err := wkc.computeBaseMetadata()
	if err != nil {
		return nil, err
	}

	appUrl := common.EnvConfig.AppURL
	internalAppUrl := common.EnvConfig.InternalAppURL

	config["userinfo_endpoint"] = internalAppUrl + "/api/oidc/userinfo"
	config["end_session_endpoint"] = appUrl + "/api/oidc/end-session"
	config["claims_supported"] = []string{"sub", "given_name", "family_name", "name", "display_name", "email", "email_verified", "preferred_username", "picture", "groups", "auth_time", "amr"}
	config["request_parameter_supported"] = true
	config["request_uri_parameter_supported"] = false
	config["request_object_signing_alg_values_supported"] = []string{"none"}
	config["prompt_values_supported"] = []string{"none", "login", "consent", "select_account"}
	config["client_id_metadata_document_supported"] = common.EnvConfig.CIMDEnabled

	return json.Marshal(config)
}

// computeOAuthASMetadata returns the RFC 8414 OAuth 2.0 Authorization Server metadata document.
func (wkc *WellKnownController) computeOAuthASMetadata() ([]byte, error) {
	config, err := wkc.computeBaseMetadata()
	if err != nil {
		return nil, err
	}

	return json.Marshal(config)
}
