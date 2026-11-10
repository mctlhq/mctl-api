# Glovo pilot: explicit team grant and per-principal allowlist

Default off. Nothing here runs unless `GLOVO_ENABLED=true` and every readiness
dependency is present; with it unset every OAuth flow is unchanged and no grant
is created or read. `GLOVO_MCP_RESOURCE` alone never opens anything.

## Flow

1. `/oauth/authorize` for the Glovo resource. A `tenant` or `selected_tenant`
   parameter is refused `invalid_request`.
2. After sign-in, `/oauth/consent` is shown for **every** client kind. It lists
   only teams where the principal holds a live principal-mode role AND has a
   `glovo_pilot_allowlist` row, minus `GLOVO_NON_SELECTABLE_TENANTS` (default
   `admins`). No option is preselected, even with one eligible team. Zero
   eligible: `access_denied`. An unreadable membership or allowlist: a retry
   page (503), never a shorter list.
3. The decision must carry exactly one `tenant`, member of the eligibility
   recomputed at decision time. It creates a `pending` row in
   `oauth_team_grants` (superseding any earlier grant of the same principal,
   client and resource) and binds the authorization code to it.
4. Code exchange inserts the refresh token and activates the grant in one
   transaction (`refreshstore.PostgresStore.InsertBound`, `teamgrant.ActivateTx`).
   Zero rows updated (expired, superseded, revoked, mismatched) is
   `invalid_grant` and nothing commits. The access token is signed after the
   commit and carries `tgr` (grant id) and `stn` (selected tenant), only on the
   Glovo audience, which must be the single `aud`.
5. Refresh reads the grant and live eligibility inside the rotation transaction
   (`RotateIfTx`), never writes there, and carries the same grant forward. A lost
   grant or team revokes grant and family in a write after the refusal. A store
   failure is `server_error` and spends nothing. A `tenant` parameter at the
   token endpoint is `invalid_request`.
6. RFC 7009 revoke, reuse detection, auth-method downgrade and
   `RevokePrincipalSessions` revoke the grant in the same transaction as the
   family. A failed revoke is a 503 on `/oauth/revoke`, never a 200.

`oauth_team_grants` and `oauth_refresh_tokens.team_grant_id` are created by the
refresh store schema whether or not Glovo is on (additive, inert).

## Scope resolver (`internal/glovo/scope`)

`Resolver.Resolve(ctx, *auth.User)` takes no other input: a Glovo-audience human
(not an agent run, service, CI, support token or relayed surface), the `tgr`
and `stn` claims, the server-held grant, live membership of `stn`, the allowlist
row. Admin status is never consulted and nothing defaults to `labs`: a member of
`labs` may select it explicitly only if individually allowlisted.

| Condition | Code (status) |
|---|---|
| wrong audience, agent, service, relayed identity | `not_authorized` (403) |
| no claims, unknown/pending/revoked/expired/mismatched grant | `ambiguous_tenant` (403) |
| tenant non-selectable | `scope_unsupported` (403) |
| membership lost | `no_tenant` (403) |
| allowlist row absent | `not_in_pilot` (403) |
| any store, membership or allowlist read failed | `unavailable` (503) |
| switch off or a dependency missing | `not_ready` (503) |

## Allowlist administration

`PUT|DELETE /api/v1/glovo/pilot/{tenant}/principals/{principal_id}`: human
platform administrators only (`isHumanAdmin`; a tenant owner who is not an admin,
a service user, an agent token and a relayed surface get 403). The principal must
be a `prn_` id; there is no tenant-wide or wildcard entry. Unknown tenant 404,
tenant lookup or store failure 503. A removal takes effect on the next Glovo
request and the next refresh.

## Configuration

| Variable | Meaning |
|---|---|
| `GLOVO_ENABLED` | `true`/`false`, default `false`. The one kill switch. |
| `GLOVO_MCP_RESOURCE` | RFC 8707 resource (slice 1). |
| `GLOVO_NON_SELECTABLE_TENANTS` | comma list, default `admins`. Empty means the default. |
| `GLOVO_DB_URL`, `GLOVO_DB_RUNTIME_ROLE`, `GLOVO_DB_MIGRATION_ROLE` | the Glovo store (allowlist reads and writes). |

With `GLOVO_ENABLED=true` the boot is refused without `TENANT_AUTHZ_MODE=principal`,
an explicit `OAUTH_DB_URL` and the Postgres refresh store, `GLOVO_MCP_RESOURCE`,
or the Glovo store settings. The in-memory refresh store and the in-memory grant
store can never open the resource.

## Rollback

Set `GLOVO_ENABLED=false`. To end live pilot sessions at once:
`UPDATE oauth_team_grants SET state='revoked', revoked_reason='rollback'`. The
additive DDL may stay.
