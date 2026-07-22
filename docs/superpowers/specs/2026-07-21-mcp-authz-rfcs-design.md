# MCP AuthN/AuthZ — RFC 8707, RFC 8414, OIDC Dynamic Client Registration 1.0

Date: 2026-07-21
Branch: `mcp` (on top of `cimd`), in both `pocket-id` and `fosite`
Status: Approved design — pending implementation plan

## 1. Goal & Scope

Add the OAuth/OIDC capabilities the Model Context Protocol (MCP) authorization
spec (draft, 2025-11-25) expects from an Authorization Server (AS):

- **RFC 8707 — Resource Indicators for OAuth 2.0.** Let clients bind an issued
  access token to a specific protected resource (the MCP server) via the
  `resource` request parameter, so the token's `aud` names that resource.
- **RFC 8414 — OAuth 2.0 Authorization Server Metadata.** Serve
  `/.well-known/oauth-authorization-server` so MCP clients can discover
  endpoints and capabilities.
- **OpenID Connect Dynamic Client Registration 1.0 + RFC 7592.** Let MCP
  clients register themselves with no prior credentials, and manage the
  resulting client (read/update/delete) with a registration access token.

Pocket ID is the **Authorization Server**, not the MCP resource server.
Therefore **RFC 9728 (Protected Resource Metadata) is out of scope** — that
document is published by MCP resource servers, which point back to this AS's
metadata.

`fosite` holds OAuth-generic behavior; `pocket-id` holds database, HTTP
endpoints, configuration, and frontend. Pocket ID consumes a fork of fosite
(`github.com/jfroy/fosite`) via a `replace` directive.

## 2. Current State (relevant facts)

- `OidcClientType` enum in `backend/internal/model/oidc.go` already has
  `standard` and `cimd`. CIMD established the pattern this design reuses:
  synthesized/managed client type, `MetadataExpiresAt`, a retention window
  (`dynamicClientRetentionDays` app-config value), the
  `clearInactiveDynamicClients` cleanup job, and an `_ENABLED` env gate
  (`CIMD_ENABLED`).
- Discovery today: only `/.well-known/openid-configuration`, precomputed in
  `well_known_controller.go::computeOIDCConfiguration`. It already advertises
  PKCE `S256` and `client_id_metadata_document_supported`.
- fosite already has RFC 8707 **validation** scaffolding
  (`resource_indicator.go`: `GetResourceIndicator`, `ValidateResourceIndicator`,
  `IsValidResourceIndicatorURI`), wired into `authorize_request_handler.go` and
  `access_request_handler.go`. It validates the `resource` form value but does
  **not** yet bind it to the token audience.
- fosite audience model: `GetRequestedAudience()` (from the legacy `audience`
  param) is checked against `client.GetAudience()` by
  `ExactAudienceMatchingStrategy`, then granted via `GrantAudience`. Pocket ID
  already wraps granted audience with `withIdentityAudience` in
  `internal/oidc/access_token_scope.go`.
- fosite provider is composed in `backend/internal/oidc/provider.go`
  (`AudienceMatchingStrategy: fosite.ExactAudienceMatchingStrategy`).
- fosite has **no** dynamic client registration.
- App configuration is actor-based in `backend/internal/appconfig` (read via
  `GetConfig(ctx)`; helpers such as `GetDynamicClientRetention()` and
  `GetCIMDURLAllowlist()` already exist).
- Client creation path: `OidcService.CreateClient` /
  `OidcService.CreateClientSecret` in `internal/service/oidc_service.go`.

## 3. Phasing

One design, one implementation plan, three phases in dependency order:

1. **RFC 8707** (fosite; pocket-id picks up new behavior).
2. **RFC 8414** (pocket-id).
3. **OIDC DCR 1.0 + RFC 7592** (pocket-id, minor fosite).

Ordering lets the Phase 2 metadata document advertise `resource`-support and,
once Phase 3 lands, `registration_endpoint`.

## 4. Phase 1 — RFC 8707 Resource Indicators (fosite)

**Policy: permissive echo.** Accept any syntactically valid absolute resource
URI without a fragment (already enforced by `IsValidResourceIndicatorURI`). No
allowlist and no per-client resource registry — the resource server validates
`aud` itself. A single `resource` value is supported (fosite already rejects
multiples).

**Mechanism** (settled after tracing fosite's audience internals):

- The access token's `aud` is serialized from `GetGrantedAudience()`
  (`handler/oauth2/strategy_jwt.go`). Granted audience persists from the
  authorize request into the code session (via `Sanitize`) and is copied to the
  token at the token endpoint (`flow_authorize_code_token.go`); refresh re-grants
  it from the original request (`flow_refresh.go`).
- **Direct grant:** after `ValidateResourceIndicator` succeeds, grant the
  resource value directly as an audience on the request. Do this at both points
  where fosite already validates the resource: the authorize request handler
  (covers authorization-code and implicit) and the access request handler
  (covers client-credentials, device, refresh re-issue). Because granted
  audience persists and is copied forward, the resource reaches the token `aud`
  across all flows without per-flow changes.
- **Permissive matching strategy:** refresh (and any re-validation) checks the
  granted audience against `client.GetAudience()` through the configured
  `AudienceMatchingStrategy`. `ExactAudienceMatchingStrategy` would reject a
  resource URI the client never declared. Add a fosite
  `ResourceIndicatorAudienceMatchingStrategy` that wraps a base strategy and
  additionally accepts any value that is a valid absolute resource-indicator URI
  (`IsValidResourceIndicatorURI`). pocket-id wires this into the provider in
  place of the bare exact strategy. This *is* the permissive-echo policy: any
  syntactically valid resource URI is an acceptable audience; the resource
  server enforces `aud`.
- No separate authorize-time/token-time subset enforcement is needed: permissive
  echo means a client could request any resource anyway, so token-time values
  are simply granted the same way. The legacy `audience` parameter path is
  unchanged — the wrapped base strategy still governs it exactly.
- Composition with `withIdentityAudience` is preserved (identity-scope tokens
  still add the issuer to `aud`).

**Scope of change:** fosite handlers for authorization-code (authorize + token),
refresh, device, and client-credentials flows, plus wherever the granted
audience is serialized into the access token. Keep changes additive and behind
the existing granted-audience machinery so non-MCP flows are unaffected when no
`resource` is sent.

**pocket-id side:** none beyond consuming the new fosite behavior and
advertising it in Phase 2 metadata.

**Tests (fosite):** resource → `aud` on issued access token; subset enforcement
at token endpoint; propagation across refresh; no `resource` → unchanged
behavior; invalid resource → `invalid_target`.

## 5. Phase 2 — RFC 8414 AS Metadata (pocket-id)

- Add `GET /.well-known/oauth-authorization-server`, served from a precomputed
  document like the existing OIDC config.
- Refactor `computeOIDCConfiguration` to build a shared base map consumed by
  both the OpenID configuration and the OAuth-AS metadata documents, to avoid
  drift between them.
- Fields (additive to what already exists): `issuer`, `authorization_endpoint`,
  `token_endpoint`, `jwks_uri`, `registration_endpoint` (Phase 3),
  `scopes_supported`, `response_types_supported`, `grant_types_supported`,
  `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`
  (already `["plain","S256"]`), `introspection_endpoint`,
  `pushed_authorization_request_endpoint`,
  `authorization_response_iss_parameter_supported`.
- New capability flags: `resource_indicators_supported: true` (after Phase 1).
- Serve both `application/json`. Register the route alongside the existing
  well-known routes and include it in the traced-route prefix set.

`registration_endpoint` is **always advertised** as a URL once Phase 3 lands;
the endpoint itself returns 403 when `DCR_ENABLED` is false. (Advertising a
stable URL is simpler than conditionally mutating the precomputed document, and
harmless when disabled.)

**Tests:** document is valid JSON, contains required RFC 8414 fields, endpoints
match configured app URL, and stays consistent with the OpenID configuration
document for shared fields.

## 6. Phase 3 — OIDC DCR 1.0 + RFC 7592 (pocket-id, minor fosite)

### 6.1 Client type

Add `OidcClientTypeDynamic OidcClientType = "dynamic"` as a third enum value.
Dynamic clients mirror CIMD clients:

- Basic data (name, redirect URIs, auth method, etc.) is managed via the
  registration endpoints, **read-only** in the admin UI.
- Groups and other Pocket ID-specific fields remain admin-editable.
- Subject to retention-based cleanup.

### 6.2 Registration endpoint — `POST /api/oidc/register`

- **Access:** open (no prior credentials), gated by a new `DCR_ENABLED` env
  flag, **off by default**. When disabled, the endpoint returns 403/404 and the
  metadata document does not advertise a functional registration.
- **Request body:** OIDC client metadata JSON — `redirect_uris` (required),
  `client_name`, `grant_types`, `response_types`, `token_endpoint_auth_method`,
  `scope`, `logo_uri`, etc. Unknown/unsupported members are ignored per spec.
- **Redirect-URI allowlist:** new app-config value
  `dynamicClientRedirectUriAllowlist` — a JSON array of URL patterns validated
  with the existing `utils.ValidateCallbackURLPattern` helper (same matcher
  CIMD uses). Every `redirect_uri` must match at least one pattern, else
  `invalid_redirect_uri`. An empty allowlist denies all (fail-closed).
- **Client creation:** generate `client_id`; issue a `client_secret` unless
  `token_endpoint_auth_method == "none"` (public/PKCE clients get no secret).
  Set `ClientType = dynamic`. Persist through the existing client-creation path
  where practical.
- **Registration access token (RFC 7592):** generate a registration access
  token, store only its **hash** on the client row, return the plaintext token
  and a `registration_client_uri` pointing at the configuration endpoint.
- **Response:** 201 with the registered client metadata plus `client_id`,
  `client_secret` (if any), `client_id_issued_at`,
  `client_secret_expires_at: 0`, `registration_access_token`,
  `registration_client_uri`, per OIDC DCR §3.2.
- **Registered metadata echo:** Pocket ID does not persist arbitrary DCR
  metadata (`grant_types`, `response_types`, `scope`) as distinct columns — a
  dynamic client's capabilities derive from the shared model flags. The
  register/GET/PUT responses therefore **synthesize** the metadata consistently
  from stored state: `token_endpoint_auth_method` from `IsPublic`
  (`none` vs `client_secret_basic`), `grant_types`
  (`["authorization_code","refresh_token"]`) and `response_types` (`["code"]`)
  as the supported set for dynamic clients, plus `redirect_uris` and
  `client_name`.
- **`logo_uri`:** if supplied at registration/update, the logo is fetched and
  stored through the same SSRF-guarded path standard clients use
  (`downloadAndSaveLogoFromURL`, which rejects private/loopback/link-local IPs
  on the initial request and on every redirect). The stored logo is served from
  the client's own logo endpoint; the original `logo_uri` is not echoed back.

### 6.3 Client configuration endpoint — RFC 7592

`GET/PUT/DELETE /api/oidc/register/:id`:

- **Auth:** `Authorization: Bearer <registration access token>`, compared to the
  stored hash. Only valid for `dynamic` clients. Any auth failure — unknown
  client, non-`dynamic` client, or token mismatch — returns `401
  invalid_token` (the same response for a missing client and a bad token, so
  the endpoint does not leak client existence).
- **GET:** return current client metadata (no secret; secret only at
  registration and rotation).
- **PUT:** replace client metadata; re-validate redirect URIs against the
  allowlist (a rejected URI returns `400 invalid_redirect_uri`, distinct from
  the `401` auth failures). Preserves `client_id`. If the update transitions the
  client from public to confidential, a fresh `client_secret` is issued and
  returned once; a transition to public clears the stored secret.
- **DELETE:** delete the dynamic client.

**`DCR_ENABLED` scope (intended semantics).** The env flag gates **new
registrations only**: `POST /api/oidc/register` returns `403` when disabled. The
RFC 7592 client-configuration endpoints (`GET`/`PUT`/`DELETE`) are **not** gated
by the flag — a client that already holds a valid registration access token can
continue to read, update, and delete its own registration after an admin sets
`DCR_ENABLED=false`, and existing dynamic clients continue to function as OAuth
clients. Disabling DCR stops new self-service registrations; it is not a
kill-switch for already-registered dynamic clients. (Admins can still remove a
specific dynamic client through the normal admin client management.)

### 6.4 Data model & migrations

Add to `OidcClient`:

- `RegistrationAccessTokenHash *string`

Reuse the existing `MetadataExpiresAt` + `dynamicClientRetentionDays` retention
and extend `clearInactiveDynamicClients` to also prune inactive `dynamic`
clients (in addition to `cimd`). For a dynamic client, `MetadataExpiresAt` is
used as a generic freshness timestamp: set to `now + retention` at registration
and at each RFC 7592 update, and bumped to `now + retention` on each successful
token issuance for that client. The cleanup job prunes dynamic clients whose
`MetadataExpiresAt` is in the past. A retention of 0 disables pruning (existing
`GetDynamicClientRetention` semantics).

Migrations for postgres and sqlite mirroring the CIMD migration style
(`backend/resources/migrations/{postgres,sqlite}/...`).

### 6.5 Configuration

- New env `DCR_ENABLED` (bool, default false), added to
  `internal/common/env_config.go` beside `CIMDEnabled`. It is surfaced to the
  frontend as a `dcrEnabled` boolean in the app-config response (both the public
  and `/all` variants), injected in `app_config_controller.go` exactly like
  `cimdEnabled`.
- New app-config value `dynamicClientRedirectUriAllowlist` wired through the
  actor-based `appconfig` package (model field + default `"[]"`, a
  `GetDynamicClientRedirectUriAllowlist()` helper, and DTO/validation mirroring
  `cimdUrlAllowlist`).

### 6.6 Frontend

- Dynamic clients appear in the admin OIDC-clients list with client type
  `dynamic`. Extend the existing client-type filter/column (added by CIMD).
- Client detail page: basic data read-only for `dynamic` clients (as with
  CIMD), groups and Pocket ID features editable.
- Admin application-configuration: add a control for
  `dynamicClientRedirectUriAllowlist` in the dynamic-clients config form
  introduced by CIMD. The control renders (and its value is submitted) **only
  when `dcrEnabled` is true**, mirroring how the CIMD allowlist control is gated
  on `cimdEnabled` — a hidden field must not push a stale value.

### 6.7 fosite

Minimal. Ensure public clients (`token_endpoint_auth_method: none`) combined
with PKCE compose and validate correctly. No registration logic in fosite.

**Tests (pocket-id):** metadata docs; `/register` happy path (confidential +
public); allowlist rejection; DCR-disabled rejection; RFC 7592 GET/PUT/DELETE
with valid and invalid registration access tokens; type isolation
(config endpoints reject non-dynamic clients); cleanup job prunes inactive
dynamic clients.

## 7. Cross-cutting concerns

- **Security:** DCR is open by design (MCP requirement) but fail-closed —
  disabled by default, redirect URIs restricted by a fail-closed allowlist,
  registration access tokens stored hashed, secrets returned only at
  registration/rotation. Resource indicators are permissive echo; the resource
  server is responsible for validating `aud`.
- **fosite integration:** after fosite `mcp`-branch changes land, bump the
  `replace => github.com/jfroy/fosite` pin in `backend/go.mod` to the new
  commit.
- **Discovery consistency:** the OIDC and OAuth-AS metadata documents share a
  base map so advertised capabilities cannot drift.
- **Backward compatibility:** all three features are additive and off/no-op
  unless a client sends `resource`, fetches the new metadata path, or DCR is
  explicitly enabled.

## 8. Out of scope

- RFC 9728 Protected Resource Metadata (belongs on MCP resource servers).
- Software statements / signed registration requests (OIDC DCR §3.1.1) — may be
  a future addition; not required by MCP.
- Sector identifiers, request-object registration, and other advanced OIDC DCR
  metadata not needed by MCP clients.
