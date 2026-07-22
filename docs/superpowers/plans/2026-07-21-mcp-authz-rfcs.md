# MCP AuthN/AuthZ RFCs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add RFC 8707 (Resource Indicators), RFC 8414 (AS Metadata), and OpenID Connect Dynamic Client Registration 1.0 + RFC 7592 to Pocket ID so it can serve as an MCP authorization server.

**Architecture:** OAuth-generic behavior (resource→audience binding, permissive audience matching) lands in the `fosite` fork; database, HTTP endpoints, configuration, and frontend land in `pocket-id`. Dynamic clients are a third `OidcClientType` ("dynamic") mirroring the existing CIMD client type: read-only basic data in the admin UI, redirect-URI allowlist, retention-based cleanup, and an `_ENABLED` env gate.

**Tech Stack:** Go 1.26, gin, gorm (sqlite + postgres), fork of `github.com/ory/fosite` (`github.com/jfroy/fosite`), SvelteKit frontend, testify + `-tags unit` for backend unit tests.

## Global Constraints

- Two repos: `fosite` at `/home/jfroy/Developer/pocket-id/fosite` (module `github.com/ory/fosite`), `pocket-id` at `/home/jfroy/Developer/pocket-id/pocket-id`. Both on branch `mcp`.
- pocket-id consumes fosite via `replace github.com/ory/fosite => github.com/jfroy/fosite <pseudo-version>` in `backend/go.mod`. Local fosite changes are integrated by pushing the fosite `mcp` branch and bumping the pseudo-version (Task 4).
- Backend unit tests build with `-tags unit`. Run from `backend/`: `go test -tags unit ./internal/<pkg>/...`.
- Backend full build needs an embedded frontend; when only building backend packages use `go build ./internal/...` or create a throwaway `backend/frontend/dist/index.html` (gitignored) as done previously.
- Follow existing patterns: appconfig values go through the actor-based `internal/appconfig` package; migrations come in matched postgres + sqlite pairs under `backend/resources/migrations/`; env flags live in `internal/common/env_config.go`.
- Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Never commit on the default branch (we are on `mcp`, which is correct).
- All three features are additive and default-off/no-op: no behavior change unless a client sends `resource`, fetches the new metadata path, or `DCR_ENABLED` is set.

---

# Phase 1 — RFC 8707 Resource Indicators (fosite)

Working dir for all Phase 1 tasks: `/home/jfroy/Developer/pocket-id/fosite`. Test command: `go test ./...` (fosite has no build tags).

### Task 1: Permissive resource-indicator audience matching strategy

**Files:**
- Modify: `audience_strategy.go`
- Test: `audience_strategy_test.go`

**Interfaces:**
- Consumes: existing `AudienceMatchingStrategy` type (`func(haystack, needle []string) error`) and `IsValidResourceIndicatorURI(string) bool` from `resource_indicator.go`.
- Produces: `func ResourceIndicatorAudienceMatchingStrategy(base AudienceMatchingStrategy) AudienceMatchingStrategy`.

- [ ] **Step 1: Write the failing test**

Add to `audience_strategy_test.go`:

```go
func TestResourceIndicatorAudienceMatchingStrategy(t *testing.T) {
	strategy := ResourceIndicatorAudienceMatchingStrategy(ExactAudienceMatchingStrategy)

	// Exact client audience still matches.
	require.NoError(t, strategy([]string{"https://api.example.com"}, []string{"https://api.example.com"}))

	// A valid absolute resource URI not declared by the client is accepted.
	require.NoError(t, strategy([]string{"https://api.example.com"}, []string{"https://mcp.example.com/v1"}))

	// A non-URI needle that is not whitelisted is still rejected.
	require.Error(t, strategy([]string{"https://api.example.com"}, []string{"not-a-uri"}))

	// A relative URI is rejected.
	require.Error(t, strategy([]string{"https://api.example.com"}, []string{"/relative"}))

	// Empty needle is a no-op.
	require.NoError(t, strategy([]string{}, []string{}))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./ -run TestResourceIndicatorAudienceMatchingStrategy -v`
Expected: FAIL — `undefined: ResourceIndicatorAudienceMatchingStrategy`.

- [ ] **Step 3: Write minimal implementation**

Append to `audience_strategy.go`:

```go
// ResourceIndicatorAudienceMatchingStrategy wraps a base AudienceMatchingStrategy so
// that, in addition to whatever the base strategy accepts, any needle that is a valid
// RFC 8707 absolute resource-indicator URI is accepted. This implements permissive-echo
// resource-indicator support: a client may bind a token to any syntactically valid
// resource URI, and the resource server is responsible for validating the audience.
func ResourceIndicatorAudienceMatchingStrategy(base AudienceMatchingStrategy) AudienceMatchingStrategy {
	return func(haystack []string, needle []string) error {
		if len(needle) == 0 {
			return nil
		}

		remaining := make([]string, 0, len(needle))
		for _, n := range needle {
			if IsValidResourceIndicatorURI(n) {
				continue
			}
			remaining = append(remaining, n)
		}

		if len(remaining) == 0 {
			return nil
		}
		return base(haystack, remaining)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./ -run TestResourceIndicatorAudienceMatchingStrategy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add audience_strategy.go audience_strategy_test.go
git commit -m "feat: add permissive resource-indicator audience matching strategy

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2: Grant the resource indicator as a request audience

**Files:**
- Modify: `resource_indicator.go`
- Modify: `authorize_request_handler.go:509` (the discarded `ValidateResourceIndicator` call)
- Modify: `access_request_handler.go:72` (the discarded `ValidateResourceIndicator` call)
- Test: `resource_indicator_test.go`

**Interfaces:**
- Consumes: `ValidateResourceIndicator(url.Values) (string, error)`; `Requester` interface (`GetRequestForm()`, `GrantAudience(string)`).
- Produces: `func GrantResourceIndicatorAudience(request Requester) error`.

- [ ] **Step 1: Write the failing test**

Add to `resource_indicator_test.go`:

```go
func TestGrantResourceIndicatorAudience(t *testing.T) {
	t.Run("grants a valid resource as audience", func(t *testing.T) {
		req := NewRequest()
		req.Form = url.Values{"resource": {"https://mcp.example.com/v1"}}
		require.NoError(t, GrantResourceIndicatorAudience(req))
		assert.Equal(t, Arguments{"https://mcp.example.com/v1"}, req.GetGrantedAudience())
	})

	t.Run("no resource is a no-op", func(t *testing.T) {
		req := NewRequest()
		req.Form = url.Values{}
		require.NoError(t, GrantResourceIndicatorAudience(req))
		assert.Empty(t, req.GetGrantedAudience())
	})

	t.Run("invalid resource returns an error and grants nothing", func(t *testing.T) {
		req := NewRequest()
		req.Form = url.Values{"resource": {"not a uri with spaces"}}
		require.Error(t, GrantResourceIndicatorAudience(req))
		assert.Empty(t, req.GetGrantedAudience())
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./ -run TestGrantResourceIndicatorAudience -v`
Expected: FAIL — `undefined: GrantResourceIndicatorAudience`.

- [ ] **Step 3: Write minimal implementation**

Append to `resource_indicator.go`:

```go
// GrantResourceIndicatorAudience validates the RFC 8707 `resource` parameter on the
// request form and, when present, grants it as an audience on the request. Because
// fosite serializes an access token's `aud` from the granted audience and carries
// granted audience forward through the authorization-code exchange and refresh, this
// is sufficient for the resource to appear in the issued token's audience.
//
// This is permissive-echo: any syntactically valid absolute resource URI is accepted.
// It must be paired with an AudienceMatchingStrategy that also accepts such URIs (see
// ResourceIndicatorAudienceMatchingStrategy) so that refresh re-validation succeeds.
func GrantResourceIndicatorAudience(request Requester) error {
	resource, err := ValidateResourceIndicator(request.GetRequestForm())
	if err != nil {
		return err
	}
	if resource == "" {
		return nil
	}
	request.GrantAudience(resource)
	return nil
}
```

In `authorize_request_handler.go`, replace:

```go
	if _, err = ValidateResourceIndicator(request.GetRequestForm()); err != nil {
		return request, err
	}
```

with:

```go
	if err = GrantResourceIndicatorAudience(request); err != nil {
		return request, err
	}
```

In `access_request_handler.go`, replace:

```go
	if _, err := ValidateResourceIndicator(accessRequest.GetRequestForm()); err != nil {
		return accessRequest, err
	}
```

with:

```go
	if err := GrantResourceIndicatorAudience(accessRequest); err != nil {
		return accessRequest, err
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./ -run 'TestGrantResourceIndicatorAudience|TestAuthorizeRequest|TestAccessRequest' -v`
Expected: PASS. Then run the package suites that exercise the two handlers:
Run: `go test ./`
Expected: PASS (no regressions in authorize/access request parsing).

- [ ] **Step 5: Commit**

```bash
git add resource_indicator.go resource_indicator_test.go authorize_request_handler.go access_request_handler.go
git commit -m "feat: grant RFC 8707 resource indicator as request audience

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3: Integration test — resource reaches token aud across code + refresh

**Files:**
- Test: `handler/oauth2/flow_authorize_code_token_test.go` (add a focused test) OR a new `handler/oauth2/resource_indicator_flow_test.go`.

**Interfaces:**
- Consumes: existing `AuthorizeExplicitGrantHandler` test harness in `handler/oauth2/`; `ResourceIndicatorAudienceMatchingStrategy`; `GrantResourceIndicatorAudience`.

This task proves the end-to-end behavior inside fosite before pocket-id picks it up. Use the existing table-test scaffolding in `flow_authorize_code_token_test.go` as the model for constructing an `AuthorizeExplicitGrantHandler` with a `fosite.Config` whose `AudienceMatchingStrategy` is `ResourceIndicatorAudienceMatchingStrategy(ExactAudienceMatchingStrategy)`.

- [ ] **Step 1: Write the failing test**

Create `handler/oauth2/resource_indicator_flow_test.go`. Model the handler/store/config setup on the existing `TestAuthorizeCode_PopulateTokenEndpointResponse` in `flow_authorize_code_token_test.go` (same package, so unexported helpers are available). The test:

```go
package oauth2

// Verifies that a resource granted as audience on the authorize request is copied
// onto the access token requester at the token endpoint (RFC 8707 end-to-end).
func TestResourceIndicatorFlow_AuthorizeCodeCopiesAudience(t *testing.T) {
	// 1. Build an authorize request whose form has resource=https://mcp.example.com/v1
	//    and call GrantResourceIndicatorAudience on it (simulating the authorize handler).
	// 2. Persist it as an authorize-code session in the in-memory store used by the
	//    existing tests (see flow_authorize_code_token_test.go for store construction).
	// 3. Build the token access request, run PopulateTokenEndpointResponse.
	// 4. Assert the access requester's GetGrantedAudience() contains
	//    "https://mcp.example.com/v1".
}
```

Fill the body concretely using the patterns already present in `flow_authorize_code_token_test.go` (store type, `AuthorizeExplicitGrantHandler{...}` fields, `NewAccessRequest`). Keep it minimal.

- [ ] **Step 2: Run test to verify it fails (or drives the assertion)**

Run: `go test ./handler/oauth2/ -run TestResourceIndicatorFlow -v`
Expected: initially FAIL if the assertion is wrong, then PASS once the test correctly reflects Task 2 behavior. (Task 2 already implements the behavior; this test locks it in.)

- [ ] **Step 3: Adjust test until it passes against Task 2 behavior**

No production code changes expected. If the test reveals granted audience is not carried, revisit Task 2.

- [ ] **Step 4: Run the full fosite suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add handler/oauth2/resource_indicator_flow_test.go
git commit -m "test: RFC 8707 resource indicator reaches access token audience

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4: Wire permissive strategy in pocket-id + integration proof

Working dir: `/home/jfroy/Developer/pocket-id/pocket-id`.

**Files:**
- Modify: `backend/internal/oidc/provider.go` (the `fositeConfig` literal, `AudienceMatchingStrategy` field)
- Modify: `backend/go.mod` (bump the fosite `replace` pseudo-version)
- Test: `backend/internal/oidc/provider_test.go` or an existing OIDC flow test that can assert `aud`.

**Interfaces:**
- Consumes: `fosite.ResourceIndicatorAudienceMatchingStrategy`, `fosite.ExactAudienceMatchingStrategy`.

- [ ] **Step 1: Push fosite mcp branch and bump the replace directive**

After Phase 1 fosite commits are pushed to `github.com/jfroy/fosite` branch `mcp`, from `backend/`:

```bash
cd /home/jfroy/Developer/pocket-id/pocket-id/backend
GOFLAGS=-mod=mod go get github.com/jfroy/fosite@mcp
```

This rewrites the `replace` pseudo-version to the new commit. Verify `grep fosite go.mod` shows the updated version.

- [ ] **Step 2: Write the failing test**

In `backend/internal/oidc/provider.go`, `AudienceMatchingStrategy` is currently `fosite.ExactAudienceMatchingStrategy`. Add a test asserting the provider accepts a resource URI audience. If an existing OIDC end-to-end test issues a token, extend it to pass `resource=https://mcp.example.com` and assert the decoded access token `aud` contains it. Otherwise add a unit test in `provider_test.go`:

```go
func TestProviderAudienceStrategyAcceptsResourceURIs(t *testing.T) {
	// Construct the provider config as provider.go does, then call
	// config.GetAudienceStrategy(ctx)([]string{"client-1"}, []string{"https://mcp.example.com/v1"})
	// and require.NoError.
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -tags unit ./internal/oidc/ -run TestProviderAudienceStrategyAcceptsResourceURIs -v`
Expected: FAIL — exact strategy rejects the resource URI.

- [ ] **Step 4: Change the provider config and verify**

In `provider.go`, change:

```go
		AudienceMatchingStrategy:                fosite.ExactAudienceMatchingStrategy,
```

to:

```go
		AudienceMatchingStrategy:                fosite.ResourceIndicatorAudienceMatchingStrategy(fosite.ExactAudienceMatchingStrategy),
```

Run: `go test -tags unit ./internal/oidc/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/go.mod backend/go.sum backend/internal/oidc/provider.go backend/internal/oidc/provider_test.go
git commit -m "feat: accept RFC 8707 resource indicators as token audience

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase 2 — RFC 8414 Authorization Server Metadata (pocket-id)

Working dir: `/home/jfroy/Developer/pocket-id/pocket-id`. Test command: `go test -tags unit ./internal/controller/...` from `backend/`.

### Task 5: Shared metadata base + `/.well-known/oauth-authorization-server`

**Files:**
- Modify: `backend/internal/controller/well_known_controller.go`
- Test: `backend/internal/controller/well_known_controller_test.go`

**Interfaces:**
- Consumes: existing `WellKnownController`, `computeOIDCConfiguration()`, `common.EnvConfig`, `jwtService.GetKeyAlg()`.
- Produces: `func (wkc *WellKnownController) computeBaseMetadata() (map[string]any, error)`, `computeOAuthASMetadata() ([]byte, error)`, and a new handler `oauthAuthorizationServerHandler` on route `/.well-known/oauth-authorization-server`. New field `wkc.oauthASConfig []byte`.

- [ ] **Step 1: Write the failing test**

Add to `well_known_controller_test.go` (follow the existing test's controller construction):

```go
func TestOAuthAuthorizationServerMetadata(t *testing.T) {
	// Construct the controller as the existing well-known test does, perform a GET on
	// /.well-known/oauth-authorization-server, and assert:
	body := doRequest(t, "/.well-known/oauth-authorization-server") // helper as in existing test
	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))

	assert.Equal(t, common.EnvConfig.AppURL, doc["issuer"])
	assert.Equal(t, common.EnvConfig.AppURL+"/authorize", doc["authorization_endpoint"])
	assert.NotEmpty(t, doc["jwks_uri"])
	assert.Contains(t, doc["code_challenge_methods_supported"], "S256")
	assert.Equal(t, true, doc["resource_indicators_supported"])
	assert.NotEmpty(t, doc["registration_endpoint"]) // always advertised (Phase 3 makes it functional)
}
```

If the existing test file has no request helper, construct a `gin` engine, register the controller, and use `httptest`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags unit ./internal/controller/ -run TestOAuthAuthorizationServerMetadata -v`
Expected: FAIL — route not registered.

- [ ] **Step 3: Refactor to a shared base and add the AS document**

In `well_known_controller.go`:

1. Extract the shared fields into `computeBaseMetadata()`:

```go
func (wkc *WellKnownController) computeBaseMetadata() (map[string]any, error) {
	appUrl := common.EnvConfig.AppURL
	internalAppUrl := common.EnvConfig.InternalAppURL

	alg, err := wkc.jwtService.GetKeyAlg()
	if err != nil {
		return nil, fmt.Errorf("failed to get key algorithm: %w", err)
	}

	return map[string]any{
		"issuer":                                appUrl,
		"authorization_endpoint":                appUrl + "/authorize",
		"token_endpoint":                        internalAppUrl + "/api/oidc/token",
		"introspection_endpoint":                internalAppUrl + "/api/oidc/introspect",
		"device_authorization_endpoint":         appUrl + "/api/oidc/device/authorize",
		"jwks_uri":                              internalAppUrl + "/.well-known/jwks.json",
		"registration_endpoint":                 appUrl + "/api/oidc/register",
		"grant_types_supported":                 []string{service.GrantTypeAuthorizationCode, service.GrantTypeRefreshToken, service.GrantTypeDeviceCode, service.GrantTypeClientCredentials},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"response_types_supported":              []string{"code", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{alg.String()},
		"authorization_response_iss_parameter_supported": true,
		"code_challenge_methods_supported":               []string{"plain", "S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"pushed_authorization_request_endpoint":          internalAppUrl + "/api/oidc/par",
		"require_pushed_authorization_requests":          false,
		"resource_indicators_supported":                  true,
	}, nil
}
```

2. Rewrite `computeOIDCConfiguration` to start from the base map and add the OIDC-only fields (`userinfo_endpoint`, `end_session_endpoint`, `claims_supported`, `request_parameter_supported`, `request_uri_parameter_supported`, `request_object_signing_alg_values_supported`, `prompt_values_supported`, `client_id_metadata_document_supported`), then `json.Marshal`.

3. Add `computeOAuthASMetadata()` that returns `json.Marshal(base)`.

4. In `NewWellKnownController`, precompute `wkc.oauthASConfig` and register:

```go
	wkc.oauthASConfig, err = wkc.computeOAuthASMetadata()
	if err != nil {
		slog.Error("Failed to pre-compute OAuth Authorization Server metadata document", slog.Any("error", err))
		os.Exit(1)
		return
	}
	group.GET("/.well-known/oauth-authorization-server", wkc.oauthAuthorizationServerHandler)
```

5. Add the handler:

```go
func (wkc *WellKnownController) oauthAuthorizationServerHandler(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", wkc.oauthASConfig)
}
```

6. Add `oauthASConfig []byte` to the `WellKnownController` struct.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/controller/ -run 'TestOAuthAuthorizationServerMetadata|WellKnown|OpenID' -v`
Expected: PASS. Also confirm the existing openid-configuration test still passes (shared base did not drop fields).

- [ ] **Step 5: Add the well-known route to the traced-route prefix set (if needed) and commit**

The prefix check in `router_bootstrap.go:117` already matches `"/.well-known/"`, so no change needed. Commit:

```bash
git add backend/internal/controller/well_known_controller.go backend/internal/controller/well_known_controller_test.go
git commit -m "feat: serve RFC 8414 oauth-authorization-server metadata

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase 3 — OIDC Dynamic Client Registration 1.0 + RFC 7592 (pocket-id)

Working dir: `/home/jfroy/Developer/pocket-id/pocket-id`.

### Task 6: `dynamic` client type, model field, and migrations

**Files:**
- Modify: `backend/internal/model/oidc.go`
- Create: `backend/resources/migrations/postgres/20260721120000_oidc_dynamic_client_registration.up.sql`
- Create: `backend/resources/migrations/postgres/20260721120000_oidc_dynamic_client_registration.down.sql`
- Create: `backend/resources/migrations/sqlite/20260721120000_oidc_dynamic_client_registration.up.sql`
- Create: `backend/resources/migrations/sqlite/20260721120000_oidc_dynamic_client_registration.down.sql`
- Test: `backend/internal/model/oidc_test.go` (add if helpful)

**Interfaces:**
- Produces: `model.OidcClientTypeDynamic OidcClientType = "dynamic"`; `OidcClient.RegistrationAccessTokenHash *string`; `func (c OidcClient) IsDynamic() bool`.

- [ ] **Step 1: Add the enum, model field, and helper**

In `backend/internal/model/oidc.go`:

```go
const (
	OidcClientTypeStandard OidcClientType = "standard"
	// OAuth Client ID Metadata Document
	OidcClientTypeCIMD OidcClientType = "cimd"
	// Dynamically registered via OpenID Connect Dynamic Client Registration
	OidcClientTypeDynamic OidcClientType = "dynamic"
)
```

Add to the `OidcClient` struct (next to `MetadataExpiresAt`):

```go
	RegistrationAccessTokenHash *string
```

Add helper methods near `IsMetadataDocument`:

```go
// IsDynamic reports whether the client was created via Dynamic Client Registration.
func (c OidcClient) IsDynamic() bool {
	return c.ClientType == OidcClientTypeDynamic
}

// IsSelfManaged reports whether the client's basic data is managed outside the admin
// UI (CIMD documents and dynamically-registered clients).
func (c OidcClient) IsSelfManaged() bool {
	return c.ClientType == OidcClientTypeCIMD || c.ClientType == OidcClientTypeDynamic
}
```

- [ ] **Step 2: Write the migrations**

`postgres/...up.sql`:

```sql
ALTER TABLE oidc_clients
    ADD COLUMN registration_access_token_hash TEXT;
```

`postgres/...down.sql`:

```sql
ALTER TABLE oidc_clients
    DROP COLUMN registration_access_token_hash;
```

`sqlite/...up.sql`:

```sql
PRAGMA foreign_keys= OFF;
BEGIN;

ALTER TABLE oidc_clients
    ADD COLUMN registration_access_token_hash TEXT;

COMMIT;
PRAGMA foreign_keys= ON;
```

`sqlite/...down.sql`:

```sql
PRAGMA foreign_keys= OFF;
BEGIN;

ALTER TABLE oidc_clients
    DROP COLUMN registration_access_token_hash;

COMMIT;
PRAGMA foreign_keys= ON;
```

- [ ] **Step 3: Build to verify the model compiles and migrations are embedded**

Run: `go build ./internal/model/... ./internal/... 2>&1 | grep -v sqlite3 | grep -v warning`
Expected: no errors. (Migrations are embedded via the resources FS; a smoke test in Task 10 exercises them by opening a test DB.)

- [ ] **Step 4: Commit**

```bash
git add backend/internal/model/oidc.go backend/resources/migrations/postgres/20260721120000_* backend/resources/migrations/sqlite/20260721120000_*
git commit -m "feat: add dynamic client type and registration access token column

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 7: `dynamicClientRedirectUriAllowlist` app-config value

**Files:**
- Modify: `backend/internal/appconfig/model.go` (struct field + default)
- Modify: `backend/internal/appconfig/service.go` (validation in `UpdateAppConfig`, `GetDynamicClientRedirectUriAllowlist` helper)
- Modify: `backend/internal/dto/app_config_dto.go` (DTO field)
- Test: `backend/internal/appconfig/service_test.go`

**Interfaces:**
- Consumes: existing `utils.ValidateCallbackURLPattern(string) error`, `common.InvalidCIMDURLPatternError` pattern (add an analogous error), `GetConfig(ctx)`.
- Produces: `AppConfigModel.DynamicClientRedirectUriAllowlist AppConfigValue` with json tag `dynamicClientRedirectUriAllowlist`; `func (s *AppConfigService) GetDynamicClientRedirectUriAllowlist() []string`; DTO field `DynamicClientRedirectUriAllowlist string`.

- [ ] **Step 1: Write the failing test**

Add to `backend/internal/appconfig/service_test.go`, modeled on `TestService_CIMDURLAllowlist`:

```go
func TestService_DynamicClientRedirectUriAllowlist(t *testing.T) {
	t.Run("defaults to empty", func(t *testing.T) {
		setUIConfigDisabled(t, false)
		db := testutils.NewDatabaseForTest(t)
		svc := newActorBackedService(t, db)
		assert.Empty(t, svc.GetDynamicClientRedirectUriAllowlist())
	})

	t.Run("round-trips a valid allowlist", func(t *testing.T) {
		setUIConfigDisabled(t, false)
		db := testutils.NewDatabaseForTest(t)
		svc := newActorBackedService(t, db)
		_, err := svc.UpdateAppConfig(t.Context(), dto.AppConfigUpdateDto{
			AppName:                          "App",
			SessionDuration:                  "60",
			DynamicClientRedirectUriAllowlist: `["https://app.example.com/**"]`,
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"https://app.example.com/**"}, svc.GetDynamicClientRedirectUriAllowlist())
	})

	t.Run("rejects an invalid pattern", func(t *testing.T) {
		setUIConfigDisabled(t, false)
		db := testutils.NewDatabaseForTest(t)
		svc := newActorBackedService(t, db)
		_, err := svc.UpdateAppConfig(t.Context(), dto.AppConfigUpdateDto{
			AppName:                          "App",
			SessionDuration:                  "60",
			DynamicClientRedirectUriAllowlist: `["javascript:alert(1)"]`,
		})
		require.Error(t, err)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags unit ./internal/appconfig/ -run TestService_DynamicClientRedirectUriAllowlist -v`
Expected: FAIL — DTO field and helper undefined.

- [ ] **Step 3: Implement the config value**

In `model.go`, next to the CIMD fields:

```go
	DynamicClientRedirectUriAllowlist AppConfigValue `json:"dynamicClientRedirectUriAllowlist"` // JSON-encoded array of strings
```

Default in `getDefaultConfig()`:

```go
	DynamicClientRedirectUriAllowlist: "[]",
```

In `dto/app_config_dto.go`, next to `CIMDURLAllowlist`:

```go
	DynamicClientRedirectUriAllowlist string `json:"dynamicClientRedirectUriAllowlist" binding:"omitempty,json"`
```

In `service.go` `UpdateAppConfig`, after the CIMD allowlist validation block, add the same shape for the new value:

```go
	if input.DynamicClientRedirectUriAllowlist != "" {
		var patterns []string
		if err := json.Unmarshal([]byte(input.DynamicClientRedirectUriAllowlist), &patterns); err != nil {
			return nil, &common.InvalidCIMDURLPatternError{Pattern: input.DynamicClientRedirectUriAllowlist}
		}
		for _, p := range patterns {
			if err := utils.ValidateCallbackURLPattern(p); err != nil {
				return nil, &common.InvalidCIMDURLPatternError{Pattern: p}
			}
		}
	}
```

Add the helper next to `GetCIMDURLAllowlist`:

```go
// GetDynamicClientRedirectUriAllowlist returns the redirect-URI patterns a
// dynamically-registered client may declare. An empty slice denies all (fail-closed).
func (s *AppConfigService) GetDynamicClientRedirectUriAllowlist() []string {
	cfg, err := s.GetConfig(context.Background())
	if err != nil {
		return nil
	}
	raw := string(cfg.DynamicClientRedirectUriAllowlist)
	if raw == "" {
		return nil
	}
	var patterns []string
	if err := json.Unmarshal([]byte(raw), &patterns); err != nil {
		return nil
	}
	return patterns
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/appconfig/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/appconfig/model.go backend/internal/appconfig/service.go backend/internal/appconfig/service_test.go backend/internal/dto/app_config_dto.go
git commit -m "feat: add dynamic client redirect URI allowlist config

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 8: `DCR_ENABLED` env flag

**Files:**
- Modify: `backend/internal/common/env_config.go`
- Test: covered by usage in Task 12; add a trivial default test only if the package has an env-config test.

**Interfaces:**
- Produces: `common.EnvConfig.DCREnabled bool` (env `DCR_ENABLED`, default false).

- [ ] **Step 1: Add the field**

In `env_config.go`, next to `CIMDEnabled`:

```go
	DCREnabled                bool             `env:"DCR_ENABLED"`
```

- [ ] **Step 2: Build to verify**

Run: `go build ./internal/common/...`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add backend/internal/common/env_config.go
git commit -m "feat: add DCR_ENABLED env flag

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 9: Registration DTOs and redirect-URI allowlist validation

**Files:**
- Create: `backend/internal/dto/oidc_registration_dto.go`
- Create: `backend/internal/oidc/registration_validate.go` (pure validation helper, no DB)
- Test: `backend/internal/oidc/registration_validate_test.go`

**Interfaces:**
- Consumes: `utils.MatchesAnyURLPattern(patterns []string, input string) bool` (from `internal/utils/callback_url_util.go`) — reports whether `input` matches any of the allowlist patterns.
- Produces:
  - `dto.OidcClientRegistrationRequestDto` (fields: `RedirectURIs []string json:"redirect_uris"`, `ClientName string json:"client_name"`, `GrantTypes []string json:"grant_types"`, `ResponseTypes []string json:"response_types"`, `TokenEndpointAuthMethod string json:"token_endpoint_auth_method"`, `Scope string json:"scope"`, `LogoURI string json:"logo_uri"`).
  - `dto.OidcClientRegistrationResponseDto` (the request fields plus `ClientID string json:"client_id"`, `ClientSecret string json:"client_secret,omitempty"`, `ClientIDIssuedAt int64 json:"client_id_issued_at"`, `ClientSecretExpiresAt int64 json:"client_secret_expires_at"`, `RegistrationAccessToken string json:"registration_access_token"`, `RegistrationClientURI string json:"registration_client_uri"`).
  - `func ValidateRegistrationRedirectURIs(redirectURIs []string, allowlist []string) error` returning a spec error when a URI matches no pattern or the list is empty.

- [ ] **Step 1: Write the failing test**

`registration_validate_test.go`:

```go
package oidc

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags unit ./internal/oidc/ -run TestValidateRegistrationRedirectURIs -v`
Expected: FAIL — `undefined: ValidateRegistrationRedirectURIs`.

- [ ] **Step 3: Implement the validator**

First confirm the concrete matcher in `internal/utils/callback_url_util.go` (the function that tests a URL against a single pattern — used by CIMD to match a document URL). Then in `registration_validate.go`:

```go
package oidc

import (
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
)

// ValidateRegistrationRedirectURIs ensures at least one redirect URI is present and
// every redirect URI matches at least one allowlist pattern. An empty allowlist denies
// all registrations (fail-closed).
func ValidateRegistrationRedirectURIs(redirectURIs []string, allowlist []string) error {
	if len(redirectURIs) == 0 {
		return &common.ValidationError{Message: "at least one redirect_uri is required"}
	}
	for _, uri := range redirectURIs {
		if !utils.MatchesAnyURLPattern(allowlist, uri) {
			return &common.ValidationError{Message: "redirect_uri '" + uri + "' is not permitted"}
		}
	}
	return nil
}
```

Create `oidc_registration_dto.go` with the two DTO structs described in Interfaces.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/oidc/ -run TestValidateRegistrationRedirectURIs -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/dto/oidc_registration_dto.go backend/internal/oidc/registration_validate.go backend/internal/oidc/registration_validate_test.go
git commit -m "feat: add DCR registration DTOs and redirect URI validation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 10: `OidcService.RegisterDynamicClient`

**Files:**
- Modify: `backend/internal/service/oidc_service.go`
- Create: `backend/internal/service/oidc_registration.go` (keep registration logic in its own file; `OidcService` methods can live in a second file of the same package)
- Test: `backend/internal/service/oidc_registration_test.go`

**Interfaces:**
- Consumes: `s.db`, `dto.OidcClientRegistrationRequestDto`, `oidc.ValidateRegistrationRedirectURIs`, `s.appConfigService`-equivalent access to the allowlist and retention. **Note:** `OidcService` no longer holds `appConfigService` (removed during the rebase). Add a dependency: pass the allowlist and retention values in, or add an `appConfigService *appconfig.AppConfigService` field to `OidcService` and wire it in `services_bootstrap.go`. Prefer adding the field back (now typed `*appconfig.AppConfigService`) since registration needs both the allowlist and the retention window.
- Produces:
  - `func (s *OidcService) RegisterDynamicClient(ctx context.Context, input dto.OidcClientRegistrationRequestDto) (model.OidcClient, string, string, error)` returning the created client, the plaintext client secret (empty for public clients), and the plaintext registration access token.
  - unexported `generateRegistrationAccessToken() (plaintext string, hash string, err error)`.

- [ ] **Step 1: Add the appConfigService field back to OidcService**

In `oidc_service.go`, add `appConfigService *appconfig.AppConfigService` to the struct, the constructor param, and the assignment. Update the `NewOidcService` call in `backend/internal/bootstrap/services_bootstrap.go` to pass `svc.appConfigService` (import `internal/appconfig` if needed). Update the test callers of `NewOidcService` to pass an extra `nil` argument.

Run: `go build ./internal/service/... ./internal/bootstrap/...` (with a throwaway `backend/frontend/dist/index.html`) — expect no errors.

- [ ] **Step 2: Write the failing test**

`oidc_registration_test.go` (build tag `unit`):

```go
func TestRegisterDynamicClient(t *testing.T) {
	// Build an OidcService with a test DB and an appConfigService whose
	// dynamicClientRedirectUriAllowlist is ["https://app.example.com/**"] and
	// dynamicClientRetentionDays is "180" (use appconfig.NewTestAppConfigService with
	// a config model, and set common.EnvConfig.UiConfigDisabled = true so GetConfig
	// reads the in-memory config — mirror db_cleanup_job_test.go).

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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -tags unit ./internal/service/ -run TestRegisterDynamicClient -v`
Expected: FAIL — `RegisterDynamicClient` undefined.

- [ ] **Step 4: Implement `RegisterDynamicClient`**

In `oidc_registration.go`:

```go
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
```

`model.UrlList` is `[]string` (in `internal/model/oidc.go`), so `model.UrlList(input.RedirectURIs)` is valid. `datatype.DateTime(time.Now().Add(retention))` matches the construction used in `db_cleanup_job_test.go`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -tags unit ./internal/service/ -run TestRegisterDynamicClient -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/service/oidc_service.go backend/internal/service/oidc_registration.go backend/internal/service/oidc_registration_test.go backend/internal/bootstrap/services_bootstrap.go backend/internal/service/oidc_service_test.go
git commit -m "feat: implement dynamic client registration service

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 11: RFC 7592 client-configuration service methods

**Files:**
- Modify: `backend/internal/service/oidc_registration.go`
- Test: `backend/internal/service/oidc_registration_test.go`

**Interfaces:**
- Produces:
  - `func (s *OidcService) GetDynamicClient(ctx context.Context, clientID, registrationAccessToken string) (model.OidcClient, error)`
  - `func (s *OidcService) UpdateDynamicClient(ctx context.Context, clientID, registrationAccessToken string, input dto.OidcClientRegistrationRequestDto) (model.OidcClient, error)`
  - `func (s *OidcService) DeleteDynamicClient(ctx context.Context, clientID, registrationAccessToken string) error`
  - unexported `authenticateDynamicClient(ctx, clientID, token) (model.OidcClient, error)` returning a not-found/forbidden error when the client is not `dynamic` or the token hash does not match.

- [ ] **Step 1: Write the failing tests**

Add to `oidc_registration_test.go`:

```go
func TestDynamicClientConfiguration(t *testing.T) {
	// Register a confidential dynamic client, capturing clientID + regToken.

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
		// create a standard client directly in the DB, then:
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -tags unit ./internal/service/ -run TestDynamicClientConfiguration -v`
Expected: FAIL — methods undefined.

- [ ] **Step 3: Implement the methods**

```go
func (s *OidcService) authenticateDynamicClient(ctx context.Context, clientID, token string) (model.OidcClient, error) {
	var client model.OidcClient
	if err := s.db.WithContext(ctx).First(&client, "id = ?", clientID).Error; err != nil {
		return model.OidcClient{}, err
	}
	if !client.IsDynamic() || client.RegistrationAccessTokenHash == nil {
		return model.OidcClient{}, &common.ValidationError{Message: "client is not a dynamically registered client"}
	}
	if bcrypt.CompareHashAndPassword([]byte(*client.RegistrationAccessTokenHash), []byte(token)) != nil {
		return model.OidcClient{}, &common.ValidationError{Message: "invalid registration access token"}
	}
	return client, nil
}

func (s *OidcService) GetDynamicClient(ctx context.Context, clientID, token string) (model.OidcClient, error) {
	return s.authenticateDynamicClient(ctx, clientID, token)
}

func (s *OidcService) UpdateDynamicClient(ctx context.Context, clientID, token string, input dto.OidcClientRegistrationRequestDto) (model.OidcClient, error) {
	client, err := s.authenticateDynamicClient(ctx, clientID, token)
	if err != nil {
		return model.OidcClient{}, err
	}
	allowlist := s.appConfigService.GetDynamicClientRedirectUriAllowlist()
	if err := oidc.ValidateRegistrationRedirectURIs(input.RedirectURIs, allowlist); err != nil {
		return model.OidcClient{}, err
	}
	client.Name = input.ClientName
	client.CallbackURLs = model.UrlList(input.RedirectURIs)
	client.IsPublic = input.TokenEndpointAuthMethod == "none"
	client.PkceEnabled = client.IsPublic
	if retention := s.appConfigService.GetDynamicClientRetention(); retention > 0 {
		expires := datatype.DateTime(time.Now().Add(retention))
		client.MetadataExpiresAt = &expires
	}
	if err := s.db.WithContext(ctx).Save(&client).Error; err != nil {
		return model.OidcClient{}, err
	}
	return client, nil
}

func (s *OidcService) DeleteDynamicClient(ctx context.Context, clientID, token string) error {
	client, err := s.authenticateDynamicClient(ctx, clientID, token)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Delete(&client).Error
}
```

Add the `common` import to the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/service/ -run TestDynamicClientConfiguration -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/service/oidc_registration.go backend/internal/service/oidc_registration_test.go
git commit -m "feat: implement RFC 7592 dynamic client configuration methods

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 12: Registration HTTP endpoints + DCR_ENABLED gate

**Files:**
- Create: `backend/internal/controller/oidc_registration_controller.go`
- Modify: `backend/internal/bootstrap/router_bootstrap.go` (register the controller near `NewOidcController`)
- Test: `backend/internal/controller/oidc_registration_controller_test.go`

**Interfaces:**
- Consumes: `service.OidcService.RegisterDynamicClient/GetDynamicClient/UpdateDynamicClient/DeleteDynamicClient`, `common.EnvConfig.DCREnabled`, `common.EnvConfig.AppURL`.
- Produces: routes `POST /api/oidc/register`, `GET/PUT/DELETE /api/oidc/register/:id` (unauthenticated by the browser/admin middleware; the configuration routes authenticate via the registration access token in the `Authorization: Bearer` header).

- [ ] **Step 1: Write the failing test**

`oidc_registration_controller_test.go`: build a gin engine, register the controller with a service backed by a test DB + allowlist (as in Task 10), set `common.EnvConfig.DCREnabled = true`, and:

```go
func TestRegistrationEndpoint(t *testing.T) {
	t.Run("registers a client when DCR is enabled", func(t *testing.T) {
		body := `{"redirect_uris":["https://app.example.com/cb"],"client_name":"C","token_endpoint_auth_method":"client_secret_basic"}`
		resp := post(t, "/api/oidc/register", body) // helper using httptest
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags unit ./internal/controller/ -run TestRegistrationEndpoint -v`
Expected: FAIL — controller undefined.

- [ ] **Step 3: Implement the controller**

```go
package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/service"
)

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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": err.Error()})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
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
	client, err := rc.oidcService.UpdateDynamicClient(c.Request.Context(), c.Param("id"), bearerToken(c), input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.OidcClientRegistrationResponseDto{
		ClientID:              client.ID,
		ClientName:            client.Name,
		RedirectURIs:          []string(client.CallbackURLs),
		RegistrationClientURI: rc.registrationClientURI(client.ID),
	})
}

func (rc *OidcRegistrationController) deleteHandler(c *gin.Context) {
	if err := rc.oidcService.DeleteDynamicClient(c.Request.Context(), c.Param("id"), bearerToken(c)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	c.Status(http.StatusNoContent)
}
```

Register in `router_bootstrap.go` next to `controller.NewOidcController(...)`:

```go
	controller.NewOidcRegistrationController(apiGroup, svc.oidcService)
```

`model.Base.CreatedAt` is a `datatype.DateTime`; `.ToTime().Unix()` yields the issued-at epoch seconds.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/controller/ -run TestRegistrationEndpoint -v`
Expected: PASS.

- [ ] **Step 5: Add the register path to any auth-exempt route lists if required**

The registration routes must be reachable without the admin auth middleware. They are registered on `apiGroup` without `authMiddleware.Add()`, so they are already public. Confirm no global middleware blocks them (check `registerGlobalMiddleware`). Commit:

```bash
git add backend/internal/controller/oidc_registration_controller.go backend/internal/controller/oidc_registration_controller_test.go backend/internal/bootstrap/router_bootstrap.go
git commit -m "feat: add DCR registration and RFC 7592 endpoints

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 13: Extend cleanup job to dynamic clients + bump freshness on token issuance

**Files:**
- Modify: `backend/internal/job/db_cleanup_job.go` (`clearInactiveDynamicClients`)
- Modify: `backend/internal/service/oidc_service.go` or the token-issuance path in `internal/oidc/` to bump `MetadataExpiresAt` on successful token issuance for dynamic clients.
- Test: `backend/internal/job/db_cleanup_job_test.go`

**Interfaces:**
- Consumes: `model.OidcClientTypeDynamic`, `GetDynamicClientRetention()`.

- [ ] **Step 1: Write the failing test**

Extend `db_cleanup_job_test.go` `TestClearInactiveDynamicClients` to also seed a `dynamic` client with an expired `MetadataExpiresAt` and assert it is deleted, and a fresh `dynamic` client that is kept:

```go
	dynStaleID := "dyn-stale"
	dynFreshID := "dyn-fresh"
	// add to the clients slice in seed():
	{Base: model.Base{ID: dynStaleID}, Name: "dyn-stale", ClientType: model.OidcClientTypeDynamic, MetadataExpiresAt: &staleExpiry},
	{Base: model.Base{ID: dynFreshID}, Name: "dyn-fresh", ClientType: model.OidcClientTypeDynamic, MetadataExpiresAt: &freshExpiry},
	// in "deletes only inactive dynamic clients":
	require.False(t, ids[dynStaleID])
	require.True(t, ids[dynFreshID])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags unit ./internal/job/ -run TestClearInactiveDynamicClients -v`
Expected: FAIL — the query only matches `cimd`.

- [ ] **Step 3: Widen the cleanup query**

In `clearInactiveDynamicClients`, change the client-type filter to include both self-managed dynamic types:

```go
		Where("client_type IN ?", []model.OidcClientType{model.OidcClientTypeCIMD, model.OidcClientTypeDynamic}).
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -tags unit ./internal/job/ -v`
Expected: PASS.

- [ ] **Step 5: Bump freshness on token issuance (best-effort)**

In the token-issuance path (where an access token is successfully issued for a client), if the client is dynamic and retention > 0, set `MetadataExpiresAt = now + retention` and persist. Locate the issuance hook in `internal/oidc/` (the same place the client is loaded for a token request). Add a focused unit test asserting `MetadataExpiresAt` advances after issuance. If a clean hook does not exist, defer this sub-step and note it — the registration/update timestamps already bound retention; this is a refinement, not required for correctness. Keep the deferral explicit in the commit message if deferred.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/job/db_cleanup_job.go backend/internal/job/db_cleanup_job_test.go
git commit -m "feat: prune inactive dynamic clients in cleanup job

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 14: Frontend — surface dynamic clients in the admin UI

**Files:**
- Modify: `frontend/src/lib/types/oidc.type.ts` (add `dynamic` to the client-type union used by CIMD)
- Modify: `frontend/src/routes/settings/admin/oidc-clients/oidc-client-list.svelte` (type filter/column already added by CIMD — extend it to include `dynamic`)
- Modify: `frontend/src/routes/settings/admin/oidc-clients/[id]/+page.svelte` (basic data read-only for self-managed clients — extend the CIMD read-only guard to also cover `dynamic`)

**Interfaces:**
- Consumes: the client-type field on the OIDC client type and whatever read-only guard CIMD introduced (search for `cimd` in the frontend to find the exact symbols).

- [ ] **Step 1: Find the CIMD frontend touchpoints**

Run: `grep -rn "cimd" frontend/src` to locate the client-type union, the list filter/column, and the read-only guard the CIMD work added.

- [ ] **Step 2: Extend the client-type union**

In `frontend/src/lib/types/oidc.type.ts`, add `'dynamic'` to the client-type string union (wherever `'cimd'` appears).

- [ ] **Step 3: Extend the list filter/column**

In `oidc-client-list.svelte`, wherever the client-type filter/label handles `'cimd'`, add a `'dynamic'` case with a label such as "Dynamic". Follow the exact rendering pattern already there.

- [ ] **Step 4: Extend the read-only guard**

In `[id]/+page.svelte`, wherever basic data is made read-only for `cimd` clients, broaden the condition to also match `dynamic` (e.g. a helper `isSelfManaged = client.clientType === 'cimd' || client.clientType === 'dynamic'`), and use it for the read-only state and any "cannot edit basic data" notice.

- [ ] **Step 5: Verify the frontend builds**

Run from `frontend/`: `npm run check` (or the repo's type-check script; confirm in `package.json`).
Expected: no type errors.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib/types/oidc.type.ts frontend/src/routes/settings/admin/oidc-clients/oidc-client-list.svelte "frontend/src/routes/settings/admin/oidc-clients/[id]/+page.svelte"
git commit -m "feat: surface dynamic clients in the admin UI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 15: Frontend — dynamic-client redirect-URI allowlist config

**Files:**
- Modify: `frontend/src/routes/settings/admin/application-configuration/forms/app-config-dynamic-clients-form.svelte` (the CIMD dynamic-clients config form)
- Modify: `frontend/src/lib/types/application-configuration.type.ts` (add the new field)

**Interfaces:**
- Consumes: the existing `cimdUrlAllowlist` control in the dynamic-clients form (added by CIMD) as the pattern to follow; the `url-list-input.svelte` component CIMD introduced.

- [ ] **Step 1: Add the field to the config type**

In `application-configuration.type.ts`, add `dynamicClientRedirectUriAllowlist: string` (or the array/string shape used for `cimdUrlAllowlist` — match it exactly).

- [ ] **Step 2: Add the control to the form**

In `app-config-dynamic-clients-form.svelte`, duplicate the `cimdUrlAllowlist` control (likely a `url-list-input`) for `dynamicClientRedirectUriAllowlist`, with an appropriate label ("Dynamic client redirect URI allowlist") and help text. Wire it into the form's bound config object and submit payload exactly as `cimdUrlAllowlist` is wired.

- [ ] **Step 3: Add any i18n strings**

If CIMD added labels to `frontend/messages/en.json`, add matching keys for the new control.

- [ ] **Step 4: Verify the frontend builds**

Run from `frontend/`: `npm run check`.
Expected: no type errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/routes/settings/admin/application-configuration/forms/app-config-dynamic-clients-form.svelte frontend/src/lib/types/application-configuration.type.ts frontend/messages/en.json
git commit -m "feat: add dynamic client redirect URI allowlist config UI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 16: End-to-end verification

**Files:** none (verification only).

- [ ] **Step 1: Backend suite**

Run from `backend/` (with a throwaway `backend/frontend/dist/index.html`):

```bash
go build ./... && go test -tags unit ./internal/appconfig/... ./internal/service/... ./internal/controller/... ./internal/job/... ./internal/oidc/... ./internal/bootstrap/...
```

Expected: build clean, all suites PASS.

- [ ] **Step 2: fosite suite**

Run from `fosite/`: `go test ./...`
Expected: PASS.

- [ ] **Step 3: Manual metadata smoke test**

Start the backend (or use an existing integration harness) with `DCR_ENABLED=1`, then:

```bash
curl -s localhost:1411/.well-known/oauth-authorization-server | jq '{issuer, registration_endpoint, resource_indicators_supported, code_challenge_methods_supported}'
```

Expected: correct issuer, a `registration_endpoint`, `resource_indicators_supported: true`, `S256` present. (Use the project's actual dev port / launch method — confirm via the `run` skill or `.claude/launch.json`.)

- [ ] **Step 4: Manual DCR smoke test**

```bash
curl -s -X POST localhost:1411/api/oidc/register -H 'content-type: application/json' \
  -d '{"redirect_uris":["https://app.example.com/cb"],"client_name":"smoke","token_endpoint_auth_method":"none"}' | jq
```

Expected: 201-style body with `client_id`, no `client_secret` (public client), a `registration_access_token`, and a `registration_client_uri`. (Requires the redirect URI to match a configured `dynamicClientRedirectUriAllowlist` pattern.)

- [ ] **Step 5: Final commit (if any verification fixups were needed)**

Commit any small fixups discovered during verification with a `fix:` message.

---

## Notes for the implementer

- The trickiest correctness point is Phase 1: the resource reaches the token `aud` only because granted audience persists through the code exchange and refresh, and the permissive audience strategy (Task 1) lets refresh re-validation pass. Do not swap the direct-grant for a requested-audience approach without re-checking `flow_refresh.go` and `flow_authorize_code_token.go`.
- `OidcService` lost its `appConfigService` field during the earlier rebase (it was unused then). Task 10 adds it back — now genuinely used and typed `*appconfig.AppConfigService`. Update all `NewOidcService` call sites (production in `services_bootstrap.go`, tests in `oidc_service_test.go`).
- Frontend tasks intentionally reference the in-repo CIMD components as the pattern to copy; read those files first (`grep -rn cimd frontend/src`) so the new controls match exactly.
