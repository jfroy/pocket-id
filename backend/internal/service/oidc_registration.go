package service

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/oidc"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

// RegisterDynamicClient implements OIDC Dynamic Client Registration (RFC 7591) core
// registration: it validates the requested redirect URIs against the configured
// allowlist, creates a new dynamically-registered OidcClient, and returns the
// plaintext client secret (for confidential clients) and plaintext registration
// access token alongside the persisted client.
func (s *OidcService) RegisterDynamicClient(ctx context.Context, input dto.OidcClientRegistrationRequestDto) (model.OidcClient, string, string, error) {
	allowlist := s.appConfigService.GetDynamicClientRedirectUriAllowlist()
	if err := oidc.ValidateRegistrationRedirectURIs(input.RedirectURIs, allowlist); err != nil {
		return model.OidcClient{}, "", "", err
	}

	isPublic := input.TokenEndpointAuthMethod == "none"

	client := model.OidcClient{
		Name:         input.ClientName,
		CallbackURLs: model.UrlList(input.RedirectURIs),
		IsPublic:     isPublic,
		PkceEnabled:  isPublic,
		ClientType:   model.OidcClientTypeDynamic,
	}

	// Freshness timestamp for retention-based cleanup.
	if retention := s.appConfigService.GetDynamicClientRetention(); retention > 0 {
		expires := datatype.DateTime(time.Now().Add(retention))
		client.MetadataExpiresAt = &expires
	}

	var clientSecret string
	if !isPublic {
		secret, err := utils.GenerateRandomAlphanumericString(32)
		if err != nil {
			return model.OidcClient{}, "", "", err
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return model.OidcClient{}, "", "", err
		}
		clientSecret = secret
		client.Secret = string(hashed)
	}

	regToken, regHash, err := generateRegistrationAccessToken()
	if err != nil {
		return model.OidcClient{}, "", "", err
	}
	client.RegistrationAccessTokenHash = &regHash

	if err := s.db.WithContext(ctx).Create(&client).Error; err != nil {
		return model.OidcClient{}, "", "", err
	}

	return client, clientSecret, regToken, nil
}

// generateRegistrationAccessToken creates a new random registration access token
// (RFC 7591 section 3.2.1) and its bcrypt hash for storage.
func generateRegistrationAccessToken() (string, string, error) {
	token, err := utils.GenerateRandomAlphanumericString(48)
	if err != nil {
		return "", "", err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return token, string(hashed), nil
}
