package service

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/pocket-id/pocket-id/backend/internal/common"
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
		secret, hash, err := generateClientSecret()
		if err != nil {
			return model.OidcClient{}, "", "", err
		}
		clientSecret = secret
		client.Secret = hash
	}

	regToken, regHash, err := generateRegistrationAccessToken()
	if err != nil {
		return model.OidcClient{}, "", "", err
	}
	client.RegistrationAccessTokenHash = &regHash

	if err := s.db.WithContext(ctx).Create(&client).Error; err != nil {
		return model.OidcClient{}, "", "", err
	}

	// Storage operations must run outside of the DB transaction/create above.
	// The logo_uri is best-effort: a bad or unreachable URL (including one
	// rejected by the SSRF guard in downloadAndSaveLogoFromURL) must not fail
	// registration.
	if input.LogoURI != "" {
		if err := s.downloadAndSaveLogoFromURL(ctx, client.ID, input.LogoURI, true); err != nil {
			slog.WarnContext(ctx, "Failed to download dynamic client logo from logo_uri, continuing without a logo",
				slog.String("client_id", client.ID),
				slog.Any("error", err),
			)
		}
	}

	return client, clientSecret, regToken, nil
}

// authenticateDynamicClient loads a client by ID and verifies that it is a
// dynamically-registered client whose registration access token matches the
// provided plaintext token. It is the shared authentication gate for the RFC
// 7592 client-configuration endpoints (GET/PUT/DELETE).
func (s *OidcService) authenticateDynamicClient(ctx context.Context, clientID, token string) (model.OidcClient, error) {
	var client model.OidcClient
	if err := s.db.WithContext(ctx).First(&client, "id = ?", clientID).Error; err != nil {
		// Intentionally return the same auth-failure error as the other failure
		// paths below, rather than leaking whether the client exists.
		return model.OidcClient{}, &common.InvalidRegistrationTokenError{}
	}
	if !client.IsDynamic() || client.RegistrationAccessTokenHash == nil {
		return model.OidcClient{}, &common.InvalidRegistrationTokenError{}
	}
	if bcrypt.CompareHashAndPassword([]byte(*client.RegistrationAccessTokenHash), []byte(token)) != nil {
		return model.OidcClient{}, &common.InvalidRegistrationTokenError{}
	}
	return client, nil
}

// GetDynamicClient implements RFC 7592 client configuration retrieval: it
// authenticates the caller via the registration access token and returns the
// current client configuration.
func (s *OidcService) GetDynamicClient(ctx context.Context, clientID, token string) (model.OidcClient, error) {
	return s.authenticateDynamicClient(ctx, clientID, token)
}

// UpdateDynamicClient implements RFC 7592 client configuration update: it
// authenticates the caller, re-validates the requested redirect URIs against
// the configured allowlist, and persists the updated client metadata. It
// returns the plaintext client secret when a new one was (re)issued as part
// of a public-to-confidential transition, or "" otherwise.
func (s *OidcService) UpdateDynamicClient(ctx context.Context, clientID, token string, input dto.OidcClientRegistrationRequestDto) (model.OidcClient, string, error) {
	client, err := s.authenticateDynamicClient(ctx, clientID, token)
	if err != nil {
		return model.OidcClient{}, "", err
	}
	allowlist := s.appConfigService.GetDynamicClientRedirectUriAllowlist()
	if err := oidc.ValidateRegistrationRedirectURIs(input.RedirectURIs, allowlist); err != nil {
		return model.OidcClient{}, "", err
	}
	client.Name = input.ClientName
	client.CallbackURLs = model.UrlList(input.RedirectURIs)

	isPublic := input.TokenEndpointAuthMethod == "none"
	client.IsPublic = isPublic
	client.PkceEnabled = isPublic

	var clientSecret string
	switch {
	case !isPublic && client.Secret == "":
		// Public-to-confidential transition: this client never had a secret, so
		// one must be (re)issued now or it could never authenticate.
		secret, hash, err := generateClientSecret()
		if err != nil {
			return model.OidcClient{}, "", err
		}
		clientSecret = secret
		client.Secret = hash
	case isPublic:
		// Confidential-to-public transition: clear any stale secret hash.
		client.Secret = ""
	}

	if retention := s.appConfigService.GetDynamicClientRetention(); retention > 0 {
		expires := datatype.DateTime(time.Now().Add(retention))
		client.MetadataExpiresAt = &expires
	}
	if err := s.db.WithContext(ctx).Save(&client).Error; err != nil {
		return model.OidcClient{}, "", err
	}

	// Storage operations must run outside of the DB transaction/save above.
	// The logo_uri is best-effort: a bad or unreachable URL (including one
	// rejected by the SSRF guard in downloadAndSaveLogoFromURL) must not fail
	// the update.
	if input.LogoURI != "" {
		if err := s.downloadAndSaveLogoFromURL(ctx, client.ID, input.LogoURI, true); err != nil {
			slog.WarnContext(ctx, "Failed to download dynamic client logo from logo_uri, continuing without a logo",
				slog.String("client_id", client.ID),
				slog.Any("error", err),
			)
		}
	}

	return client, clientSecret, nil
}

// DeleteDynamicClient implements RFC 7592 client configuration deletion: it
// authenticates the caller and removes the client.
func (s *OidcService) DeleteDynamicClient(ctx context.Context, clientID, token string) error {
	client, err := s.authenticateDynamicClient(ctx, clientID, token)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Delete(&client).Error
}

// generateClientSecret creates a new random client secret and its bcrypt hash
// for storage. It returns the plaintext secret (to be shown to the caller once)
// and the hash (to be persisted).
func generateClientSecret() (plaintext, hash string, err error) {
	secret, err := utils.GenerateRandomAlphanumericString(32)
	if err != nil {
		return "", "", err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return secret, string(hashed), nil
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
