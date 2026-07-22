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

**Mechanism:**

- Extend the authorize and token request handling so that, after
  `ValidateResourceIndicator` succeeds, the resource value is recorded as a
  **granted audience** on the request/session. This is distinct from the legacy
  `audience` param path and deliberately bypasses
  `ExactAudienceMatchingStrategy` (permissive echo).
- Persist the authorize-time resource on the stored authorize request/session.
  At the token endpoint, if the client re-sends `resource`, enforce that
  token-time resources are a subset of authorize-time resources (RFC 8707 §2.2);
  otherwise inherit the authorize-time resource. Propagate across refresh-token
  exchange so refreshed tokens keep the same `aud`.
- The resulting access-token `aud` therefore contains the resource. Composition
  with `withIdentityAudience` must be preserved (identity-scope tokens still add
  the issuer).

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

### 6.3 Client configuration endpoint — RFC 7592

`GET/PUT/DELETE /api/oidc/register/:id`:

- **Auth:** `Authorization: Bearer <registration access token>`, compared to the
  stored hash. Only valid for `dynamic` clients; `standard`/`cimd` clients
  return 403.
- **GET:** return current client metadata (no secret; secret only at
  registration and rotation).
- **PUT:** replace client metadata; re-validate redirect URIs against the
  allowlist. Preserves `client_id`.
- **DELETE:** delete the dynamic client.

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
  `internal/common/env_config.go` beside `CIMDEnabled`.
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
  introduced by CIMD.

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
