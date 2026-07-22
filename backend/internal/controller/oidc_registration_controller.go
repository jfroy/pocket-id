package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/service"
)

// NewOidcRegistrationController registers the OIDC Dynamic Client Registration
// (RFC 7591) and Client Configuration (RFC 7592) HTTP endpoints. These routes are
// intentionally registered without the admin/browser auth middleware: the
// registration endpoint is gated by the DCR_ENABLED flag, and the client
// configuration endpoints self-authenticate via the registration access token
// supplied in the Authorization header.
func NewOidcRegistrationController(group *gin.RouterGroup, oidcService *service.OidcService) {
	rc := &OidcRegistrationController{oidcService: oidcService}
	group.POST("/oidc/register", rc.registerHandler)
	group.GET("/oidc/register/:id", rc.getHandler)
	group.PUT("/oidc/register/:id", rc.updateHandler)
	group.DELETE("/oidc/register/:id", rc.deleteHandler)
}

type OidcRegistrationController struct {
	oidcService *service.OidcService
}

func (rc *OidcRegistrationController) registrationClientURI(id string) string {
	return common.EnvConfig.AppURL + "/api/oidc/register/" + id
}

func (rc *OidcRegistrationController) registerHandler(c *gin.Context) {
	if !common.EnvConfig.DCREnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "dynamic client registration is disabled"})
		return
	}
	var input dto.OidcClientRegistrationRequestDto
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}
	client, secret, regToken, err := rc.oidcService.RegisterDynamicClient(c.Request.Context(), input)
	if err != nil {
		var validationErr *common.ValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}
	c.JSON(http.StatusCreated, dto.OidcClientRegistrationResponseDto{
		ClientID:                client.ID,
		ClientSecret:            secret,
		ClientName:              client.Name,
		RedirectURIs:            []string(client.CallbackURLs),
		ClientIDIssuedAt:        client.CreatedAt.ToTime().Unix(), // model.Base.CreatedAt is datatype.DateTime
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   rc.registrationClientURI(client.ID),
	})
}

// bearerToken extracts the registration access token from the Authorization header.
func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	h := c.GetHeader("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func (rc *OidcRegistrationController) getHandler(c *gin.Context) {
	client, err := rc.oidcService.GetDynamicClient(c.Request.Context(), c.Param("id"), bearerToken(c))
	if err != nil {
		var invalidTokenErr *common.InvalidRegistrationTokenError
		if errors.As(err, &invalidTokenErr) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}
	c.JSON(http.StatusOK, dto.OidcClientRegistrationResponseDto{
		ClientID:              client.ID,
		ClientName:            client.Name,
		RedirectURIs:          []string(client.CallbackURLs),
		RegistrationClientURI: rc.registrationClientURI(client.ID),
	})
}

func (rc *OidcRegistrationController) updateHandler(c *gin.Context) {
	var input dto.OidcClientRegistrationRequestDto
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}
	client, secret, err := rc.oidcService.UpdateDynamicClient(c.Request.Context(), c.Param("id"), bearerToken(c), input)
	if err != nil {
		var invalidTokenErr *common.InvalidRegistrationTokenError
		var validationErr *common.ValidationError
		switch {
		case errors.As(err, &invalidTokenErr):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		case errors.As(err, &validationErr):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}
	c.JSON(http.StatusOK, dto.OidcClientRegistrationResponseDto{
		ClientID:              client.ID,
		ClientSecret:          secret,
		ClientName:            client.Name,
		RedirectURIs:          []string(client.CallbackURLs),
		RegistrationClientURI: rc.registrationClientURI(client.ID),
	})
}

func (rc *OidcRegistrationController) deleteHandler(c *gin.Context) {
	if err := rc.oidcService.DeleteDynamicClient(c.Request.Context(), c.Param("id"), bearerToken(c)); err != nil {
		var invalidTokenErr *common.InvalidRegistrationTokenError
		if errors.As(err, &invalidTokenErr) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}
	c.Status(http.StatusNoContent)
}
