# Glovo connections: tenant/principal store (M1a slice 2, mctl-api#959)

This is the durable domain under the synthetic Glovo connections: typed
install and connection states, server-minted ids, a Postgres schema `glovo`
with lifecycle constraints, an immutable audit trail, and concurrency-safe
connect / reconnect / revoke / reinstall. Code: `internal/glovo`. It is the
single reference for the sibling slices #960 and #961.

Everything here is synthetic. No provider session, cookie, token, password,
email address, phone number or delivery address is stored in any table, audit
event or log line. The only secret-related value is an opaque `gsr_`
reference id.

## Non-goals of this slice

- No route, MCP tool or `cmd/api/main.go` wiring in slice 2 itself: the HTTP
  routes, the worker identity and the wiring are slice 4 (#961, see "Synthetic
  connection routes" below).
- No OAuth audience, grant or team selection (#958, #960).
- No real provider access, secret backend or KMS. `SecretRefs` has only a
  refusing implementation.
- No audit deletion API (see Retention).

## Data model

All objects live in the Postgres schema `glovo`, owned by the migration
role. Every query names its table schema-qualified, so it works on any pool
whatever its `search_path`.

| Table | Purpose |
|---|---|
| `glovo.glovo_installs` | one row per tenant (`tenant_id` unique); `install_id` `gin_<ULID>`, `install_revision` starts at 1, `state` `installed`/`uninstalled` |
| `glovo.glovo_connections` | `connection_id` `gcn_<ULID>`, owner (`tenant_id`, `principal_id` with `prn_`), `install_id` + `install_revision`, `state`, `secret_ref` (`gsr_` or NULL), `supersedes_id`, `end_reason`, `expires_at`, `version`; never deleted |
| `glovo.glovo_connect_requests` | idempotency: (`tenant_id`, `principal_id`, `idempotency_key`) -> `request_hash`, `connection_id` |
| `glovo.glovo_audit_events` | append-only: `gae_<ULID>`, subject and actor principal, `actor_kind`, entity, event, from/to state, install revision, reason, time |
| `glovo.glovo_pilot_allowlist` | read here (`IsAllowlisted`), written by #960 |
| `glovo.glovo_schema_version` | one row, the schema version `NewStore` checks |

Constraints: partial unique index `glovo_connections_one_live` (one live
connection per owner), unique (`tenant_id`, `principal_id`, `connection_id`,
`install_revision`), named CHECKs `glovo_installs_state_check`,
`glovo_connections_state_check`, `glovo_connections_principal_check`,
`glovo_connections_active_expiry_check` (an `active` row has `expires_at`),
`glovo_connections_secret_ref_check`, `glovo_connections_terminal_check`,
`glovo_pilot_allowlist_principal_check`, `glovo_audit_events_actor_kind_check`.
Index `glovo_connections_owner_recent` serves the most-recent-row read.

Triggers (always refuse, no GUC or role exception): `glovo_audit_immutable()`
on UPDATE, DELETE and TRUNCATE of `glovo_audit_events`;
`glovo_connections_no_delete()` on DELETE and TRUNCATE of `glovo_connections`.

## State diagram

```
pending_handoff -> pending_provider | failed | expired | revoked
pending_provider -> active | failed | expired | revoked
active -> expired | failed | revoked
expired, failed, revoked: terminal
```

`pending_provider -> active` is taken only inside `ActivateTx`, which steps
`pending_handoff -> pending_provider -> active` (two audited writes, one
transaction, `expires_at = clock_timestamp() + ExpiresIn`, at most 24 h).
`Transition` refuses `to = active` (`invalid_request`) from every state. A
connection resting in `pending_provider` leaves it only through `Transition`
to `failed`, `expired` or `revoked`. Wire `PublicState` (#961): both
`pending_*` map to `pending`.

## Locks (levels L1 and L2 of mctl-api#957 design 6b)

1. L1, `glovo-install/v1|<tenant>`: shared by connection writers and readers
   on the Glovo write path; exclusive by `Install`, `RevokeInstall`,
   `Reinstall`.
2. L2, `glovo-owner/v1|<tenant>|<principal>`: exclusive by every connection
   write; shared by `LockOwnerShared`.

Keys are length-prefixed. Always L1 then L2. A revoker holds L1 and L2, ends
the rows, then calls the `EndPurger` and the `RevocationHook` (which take
later levels only). `LockOwnerShared`, `LiveConnectionTx` and `ActivateTx` run
on the caller's transaction and never begin or commit.

## Store API summary

`ApplySchema(ctx, migrationConnStr, runtimeRole)` (migration role, one
transaction under `pg_advisory_xact_lock(hashtext('glovo-schema'))`);
`NewStore(ctx, pool, runtimeRole, migrationRole, opts...)` (shared pool, no
DDL, fails closed on a missing or different schema version, never closes the
pool); `Install`, `GetInstall`, `RevokeInstall`, `Reinstall`, `Connect`,
`Reconnect`, `ActivateTx`, `Transition`, `Revoke`, `RevokeForMembership`,
`GetConnection`, `GetConnectionForWorker`, `LiveConnection`,
`LiveConnectionTx`, `LockOwnerShared`, `ListAudit`, `IsAllowlisted`,
`AppendRefusal`, `Ready`. Options: `WithClock`, `WithExplicitURL`,
`WithRevocationHook`, `WithEndPurger`, `WithEndPurgerRequired`,
`WithMembershipRevoker`.

- Every connection method takes an `Owner`; a read or write by connection id
  alone does not exist (except `GetConnectionForWorker`, callable only from the
  worker handlers; a source-scan test enforces it).
- A missing id, another principal's id and another tenant's id are the same
  `ErrNotFound`, from one statement.
- `Connect`: replay lookup first (same key and arguments return the original
  with `Replayed=true`; other arguments are `idempotency_key_reused`), then
  `no_install`, `stale_install`, `AfterLocks`, insert. The partial unique
  index maps to `connection_exists`.
- `Reconnect`: a live prior is ended with reason `superseded` unless
  `TerminalOnly` (then `connection_exists`); a terminal prior, or one past
  `expires_at` (moved to `expired` first), ends nothing; always a new `gcn_`
  with `supersedes_id`.
- Every terminal path goes through one `endConnection` helper: it clears
  `secret_ref` and returns it as `ReleasedSecretRef`, appends one audit event
  per ended connection with the caller's actor, then calls the `EndPurger`
  and the `RevocationHook` on the same transaction. An error from either rolls
  the ending back.
- Expiry is judged by the database clock at statement time
  (`clock_timestamp()`, never `now()`), by `LiveConnection`,
  `LiveConnectionTx`, `ActivateTx` and the `Reconnect` terminal branch.
  `created_at` of a connection is `clock_timestamp()` set in SQL after L2.
- `LiveConnection`/`LiveConnectionTx` read the owner's most recent row and
  return the live row, or a typed code with that row: `connection_revoked`,
  `connection_expired` (state or clock), `no_connection` (failed or no row).
- Actor sources: `Actor{PrincipalID, Kind}`, kinds `user|owner|admin|worker|system`
  (`user`, `owner`, `admin` need a `prn_` principal; `worker` and `system` use
  the labels `worker` and `system`). `Install`, `RevokeInstall`, `Reinstall`,
  `Revoke`, `RevokeForMembership` take it as a parameter; `Connect`,
  `Reconnect`, `ActivateTx` in their input; `Transition` only from
  `ActorFrom(ctx)` (`WithActor`, or an authenticated Glovo worker principal in
  ctx, which yields `Actor{"worker", worker}`); with none it is
  `invalid_request`. There is no `system` default.

## Roles and grants

Role model: mctl-api#957 design 6d.1. The migration role (`glovo_migrator`)
owns schema `glovo` and every object and is the only role that runs
`ApplySchema`. The one runtime role (`glovo_runtime`) gets `USAGE` on the
schema and exactly the rows registered with `glovo.RegisterGrants` (checked in
`internal/glovo/testdata/grants.golden`):

```
glovo.glovo_audit_events: INSERT,SELECT
glovo.glovo_connect_requests: DELETE,INSERT,SELECT,UPDATE
glovo.glovo_connections: INSERT,SELECT,UPDATE
glovo.glovo_handoff_refs: DELETE,INSERT,SELECT UPDATE(consumed_at)
glovo.glovo_installs: INSERT,SELECT,UPDATE
glovo.glovo_pilot_allowlist: DELETE,INSERT,SELECT
glovo.glovo_rate_counters: DELETE,INSERT,SELECT UPDATE(count,updated_at)
glovo.glovo_schema_version: SELECT
```

The runtime role owns nothing, so it cannot `ALTER`, `DROP` or `DISABLE
TRIGGER`; it has no `CREATE`, `TRUNCATE`, `TRIGGER` or `REFERENCES`. No other
role has any right on schema `glovo`. Each later slice registers the rows for
its own tables from its own package `init` and updates the golden file in its
own PR.

`ApplySchema` refuses a runtime role name that does not match
`^[a-z_][a-z0-9_]{0,62}$`, a schema or object in `glovo` owned by another role,
and a recorded version above the compiled one.

`Ready` returns a `*NotReadyError` (matches `errors.Is(err, &glovo.Error{Code:
glovo.CodeNotReady})`) with a reason: `explicit_url_missing` (no
`WithExplicitURL(true)`; there is no `AUDIT_DB_URL` fallback; the wiring slice
must pass the pool opened from an explicit `GLOVO_DB_URL`),
`revocation_hook_missing`, `end_purger_missing` (only with
`WithEndPurgerRequired(true)`), `runtime_role_mismatch`,
`runtime_role_privileged`, `runtime_role_owns_or_is_owner`,
`schema_version_mismatch`, `object_owner_mismatch`, `schema_privileges`,
`grants_mismatch`, `table_not_registered`, `table_missing`,
`trigger_disabled_or_missing`, `check_failed`.

## Refusal codes and HTTP status (one function: `glovo.Status`)

The closed enum is `glovo.Code`; the mapping equals mctl-api#957 design 4.1.

| Status | Codes |
|---|---|
| 503 | `not_ready`, `unavailable`, and any unregistered code (written with body code `unavailable`) |
| 403 | `not_authorized`, `no_install`, `ambiguous_tenant`, `no_tenant`, `scope_unsupported`, `not_in_pilot`, `stale_install` |
| 400 | `invalid_request` |
| 404 | `not_found`, `no_connection` |
| 429 | `rate_limited` |
| 409 | `stale_version`, `connection_exists`, `connection_revoked`, `connection_expired`, `invalid_transition`, `idempotency_key_reused`, `fingerprint_changed`, `approval_invalid`, `approval_expired`, `approval_replayed`, `intent_mismatch`, `basket_changed`, `tenant_busy` |

Error body: `{"error": <code>, "error_description": <fixed text>}`, written by
`glovo.WriteError`. The 401 for a missing or invalid bearer is written only by
`glovo.WriteUnauthenticated(w, wwwAuthenticate)` (body code `not_authorized`,
`WWW-Authenticate` only when the argument is non-empty). A refusal's message is
the code and its fixed description only: no identifier, no owner data.

## Kill switch

`GLOVO_ENABLED`, default `false`, read once in `cmd/api/main.go` (introduced by
#960, reused by #961). Nothing in `internal/glovo` itself reads it.

## Retention

Audit events are append-only: UPDATE, DELETE and TRUNCATE are refused by
trigger for every role, including the owner, with no GUC or application
override (`SET LOCAL glovo.retention_sweep` does nothing). The target is to
keep audit events for 400 days, but nothing in this slice deletes or expires
them: physical deletion needs a separate, security-reviewed maintenance design
with its own database role. Install and connection rows are kept indefinitely
(connection ids are never reused). `glovo_connect_requests` rows are removed
after 24 h by the #961 sweep (the matching `DELETE` right is granted).

On any terminal transition `secret_ref` is set to NULL in the same transaction
and returned to the caller for release. The code does not call a future
per-connection data-key design "crypto-shredding": no evidence for erasure
guarantees exists.

## Tests

`go test ./internal/glovo/...` with `TEST_DATABASE_URL` pointing at a
PostgreSQL superuser. Each DB test creates its own database and two ordinary
(non-superuser) roles, applies the schema as the migration role and runs the
store as the runtime role, so the real triggers and grants are in effect;
nothing is bypassed (`session_replication_role`, trigger disablement) and no
shared table is touched. With `TEST_DATABASE_URL` unset the tests skip, except
in CI (`CI` set), where they fail.

## Manual down-migration

Only synthetic data ever exists. Run by the migration role, in this order:

```sql
DROP TRIGGER glovo_audit_events_immutable ON glovo.glovo_audit_events;
DROP TRIGGER glovo_audit_events_no_truncate ON glovo.glovo_audit_events;
DROP TRIGGER glovo_connections_no_delete ON glovo.glovo_connections;
DROP TRIGGER glovo_connections_no_truncate ON glovo.glovo_connections;
DROP FUNCTION glovo.glovo_audit_immutable();
DROP FUNCTION glovo.glovo_connections_no_delete();
DROP TABLE glovo.glovo_handoff_refs;
DROP TABLE glovo.glovo_rate_counters;
DROP TABLE glovo.glovo_connect_requests;
DROP TABLE glovo.glovo_audit_events;
DROP TABLE glovo.glovo_connections;
DROP TABLE glovo.glovo_installs;
DROP TABLE glovo.glovo_pilot_allowlist;
DROP TABLE glovo.glovo_schema_version;
-- drop schema glovo only when no other slice's table remains in it
```

# Synthetic connection routes (M1a slice 4, mctl-api#961)

Default OFF. With `GLOVO_ENABLED` unset every `/api/v1/glovo/facade/*`,
`/api/v1/glovo/tenants/*` and `/api/v1/glovo/worker/*` route answers `503
not_ready` before the body is read, and token issuance and verification are
unchanged. The only provider is `synthetic`: no cookie, consumer credential or
Glovo HTTP call exists. **Integration is NOT READY** until the canonical
facade join API (mctl-api#957) and the public facade (mctl-telegram#1235) are
merged; this slice only keeps its schemas and refusal codes compatible with
them. The approval of parent #953 does not authorize this slice.

## Prerequisite mapping (task 0)

| Joint-contract name | Where it is in the code |
|---|---|
| Glovo audience, `IsGlovoAudience`, `glovoAudienceGate` (#958) | `internal/auth`, `internal/api/glovo_audience_gate.go` |
| store, states, refusal enum, `Status`, `WriteError` (#959) | `internal/glovo` |
| `ActivateTx`, `ConnectInput.AfterLocks`, `TerminalOnly`, `AppendRefusal`, `Ready`, `GetConnectionForWorker`, `WithEndPurger`, `WithEndPurgerRequired`, `EndPurgerInstalled`, `expectedGrants` (#959) | `internal/glovo/connection.go`, `store.go`, `ready.go`, `grants.go` |
| `GLOVO_ENABLED`, `scope.Resolver`, team grant, allowlist routes (#960) | `cmd/api/glovo_team_grant.go`, `internal/glovo/scope` |
| `IsGlovoWorker`, `glovoWorkerGate` | built here: `internal/auth/glovo_worker.go`, `internal/api/handlers_glovo.go` |

## Routes

| Route | Caller | Effect |
|---|---|---|
| `GET /api/v1/glovo/facade/context` | Glovo-audience token | team, installation, the caller's recent connections |
| `POST /api/v1/glovo/facade/connections` | same, `Idempotency-Key` | 201 `pending`, or 200 `replayed:true` |
| `GET /api/v1/glovo/facade/connections/{id}` | same | owner-scoped read; foreign and missing ids are the same 404 |
| `POST .../connections/{id}/handoff` | same | issues `ghr_` + 32 random bytes (hex), only the SHA-256 is stored, TTL 10 min, single use; the connection stays `pending_handoff` |
| `POST .../connections/{id}/revoke` | same | `revoked`, idempotent |
| `POST .../connections/{id}/reconnect` | same, `Idempotency-Key` | new `gcn_` with `supersedes_id`; a live prior is `connection_exists` |
| `PUT /api/v1/glovo/tenants/{tenant}/installation` | tenant owner (strict) | install (201) or reinstall (200): revision +1, older live connections revoked in one transaction |
| `DELETE /api/v1/glovo/tenants/{tenant}/installation` | tenant owner (strict) | uninstall, all live connections revoked |
| `POST /api/v1/glovo/worker/check` | worker | `{allowed, tenant, owner_principal_id, state, expires_at}` |
| `POST /api/v1/glovo/worker/connections/{id}/activate` | worker | consumes the handoff reference and activates, atomically |
| `POST /api/v1/glovo/worker/connections/{id}/expire` | worker | synthetic, drives the expiry path |

The pilot allowlist routes (`/api/v1/glovo/pilot/...`) are #960's and are not
behind this feature gate.

Facade handlers resolve the scope with `scope.Resolver` (selected-team grant,
live membership, allowlist) and take tenant, principal and install revision
only from it and the store. The installation routes use `requireGlovoTenantOwner`:
the principal-mode role must be `owner`; `roleGate` is never consulted, so a
platform admin who is not an owner is refused and an owner who is an admin is
judged by the owner role alone.

The worker identity is `service:mctl-glovo-worker`, built by
`auth.NewGlovoWorkerUser` only when `MCTL_GLOVO_WORKER_TOKEN_FILE` names a
readable file holding a credential of at least 32 characters that equals no
other principal's token. The credential is test-only until the issuer decision
(mctl-gitops#2506, #2540); no production credential is issued by this change.
`glovoWorkerGate` confines the worker to `POST /api/v1/glovo/worker/*` (403
everywhere else: facade, `/mcp`, DevLoop, bridge, installation, `whoami`); each
worker handler also requires `IsGlovoWorker()`. An admin, the service token, a
bridge provider, a support-audience token and a Glovo-audience token are
refused on the worker routes, and the bridge provider is refused on every
`/api/v1/glovo/*` route.

Every worker handler starts with the one by-id read without an owner predicate
(`WorkerConnectionView`, the lapsed-aware form of `GetConnectionForWorker`),
takes the write-once Owner and the version from it, and passes them to the
locked primitives (`ActivateTx`, `Transition`), which re-check under L1 and L2.
`check` re-derives install state and revision, the owner's live role, the
allowlist row and the connection's state and expiry on every call.

## Wire types and schemas

`internal/glovo/wire`: one struct per body with a mandatory `schema` constant
(`glovo-connection/v1alpha1.<Type>`), a decoder (16 KiB, no unknown field, no
trailing data, exact schema; any failure is `400 invalid_request`) and the
public state (`pending_handoff` and `pending_provider` are `pending`). JSON
Schemas are committed in `internal/glovo/wire/schema/` and may be vendored by
#957 and mctl-telegram#1235. Refusals are `glovo.WriteError` bodies
(`{error, error_description}`, no `schema` field; `schema/error.json`).

## Handoff, quota and the connect service

Tables (created by `ApplySchema` under the migration role, schema version 2):
`glovo_handoff_refs` (hash-only, single use, TTL) and `glovo_rate_counters`
(`owner_hour` windows and one `tenant_mutex` row per tenant).

Lock order: connect and reconnect take L1 shared, L2 exclusive, then **L2a**
(the `tenant_mutex` row, created by `INSERT ... ON CONFLICT DO NOTHING` with
`window_start = 'epoch'`, then `FOR UPDATE`); activate takes L1 shared, L2
exclusive, then **L2b** (the `glovo_handoff_refs` row `FOR UPDATE`). Limits
(`ConnectLimits`): 10 connects or reconnects per hour per owner, and 50 live
connections per tenant (state not terminal and `expires_at` null or in the
future, database clock), counted after L2a is held. A refusal rolls the whole
connect back, so no counter moves; a replay returns before `AfterLocks` and
moves nothing. A `lock_timeout` (SQLSTATE `55P03`) on these locks is
`tenant_busy`; any other store failure is `unavailable`.

`ActivateWithHandoff` runs `ActivateTx` with an `AfterLocks` that consumes the
reference. State, revision and version checks come first, so a revoked or
expired connection reports its own code; an unknown, foreign, expired or
already-consumed reference is one `not_found` and commits nothing. The
`EndPurger` (`PurgeHandoffRefs`) deletes a connection's unconsumed references
whenever it ends. `Sweep(ctx, limit)` (a ticker that exists only while
`GLOVO_ENABLED=true`) deletes expired references, stale `owner_hour` windows
and 24 h old idempotency rows; it never deletes `tenant_mutex` rows.

`internal/glovo/connect.Service` is the one connect path, used by the facade
connect route and, later, by #957's `glovojoin.Connections` adapter. The
`handoff_url` is `GLOVO_SYNTHETIC_HANDOFF_BASE_URL` + `/` + the raw reference
(unset: `not_ready`, never an invented URL). A connection that is live in
storage but past `expires_at` is ended through `Reconnect` with `TerminalOnly`
before the new row is inserted.

`NewStore` is wired with a no-op revocation hook (the synthetic provider holds
no secret to release), `WithEndPurger(PurgeHandoffRefs)` and
`WithEndPurgerRequired(true)`. `glovoReady` requires `GLOVO_ENABLED`, the store,
`store.Ready()` nil, `EndPurgerInstalled()`, the Glovo resource, the resolver
and a configured worker credential.

## Refusals of handoff and activate

| Case | Code |
|---|---|
| unknown, foreign or never-existing connection; wrong, foreign, expired or consumed reference | `not_found` (one body) |
| connection not `pending_handoff` (`pending_provider` or `active`) | `invalid_transition` |
| revoked | `connection_revoked` |
| expired, or `expires_at` passed | `connection_expired` |
| failed | `no_connection` |
| install revision differs | `stale_install` |
| version changed under the locks | `stale_version` (nothing committed) |
| lock timeout | `tenant_busy` |
| any other failure | `unavailable` |

Refusals on a mutating route that name an existing install or connection are
appended to the audit table with `AppendRefusal`. Refusals that arrive before
any entity exists (`ambiguous_tenant`, `scope_unsupported`, `no_tenant`,
`not_in_pilot`, `no_install`, `rate_limited`) are logged with ids and codes and
counted in `mctl_glovo_route_refusals_total` only.

## Test matrix

`go test ./internal/api -run GlovoE2E` with `TEST_DATABASE_URL`
(`internal/api/glovo_e2e_*_test.go`): the real `NewRouter`, the real auth
middleware for Glovo-audience tokens minted through the real consent and token
endpoints with a selected team, the real worker credential, and the real store
on a per-test database with its own migration and runtime roles. Fixtures:
tenants `alpha` and `beta`, users `a1` and `a2` in `alpha`, `b1` in `beta`,
`u3` eligible but unselected.

| Test | Covers |
|---|---|
| `FeatureOffEveryRoute` | T1: `chi.Walk` over every glovo route, 503 `not_ready` |
| `HappyPath` | T2 |
| `Isolation` | T3: foreign and missing ids give byte-identical 404 on every id route |
| `FailClosed` | T4: no grant, unselected, system tenant, role and allowlist removed, forged body fields and headers, wrong and multi audience |
| `AuditNoLeakAndSchemas` | T5, T9: audit rows, refusal audit, secret scan of logs, audit rows and responses, schema validation |
| `Lifecycle`, `HandoffRefusalTable` | T6 |
| `IdempotencyAndLimits`, `TenantLimitRace`, `Races` | T7 (the race test holds both replicas between count and insert; it goes red with the L2a lock removed) |
| `IdentityConfinement`, `InstallationOwnerOnly` | T8, F1 |
| `Readiness` | T11 |
| `JoinPath` | T12 |
| `WorkerOwnerPath` | T13 |

## Anti-regression list

- A Glovo-audience token reaches only the facade routes (`glovoAudienceRoutes`).
- The worker reaches only `POST /api/v1/glovo/worker/*`; no admin, service,
  bridge or support credential is a substitute.
- No handler reads `glovo_connections` with SQL; the owner-less read is only in
  `handlers_glovo_worker.go`.
- A forged tenant, owner or install revision in a body is `400`; a selected-team
  header is ignored; there is no `labs` fallback.
- No MCP tool is added or changed.

## Rollback

`GLOVO_ENABLED` unset returns every route to `503 not_ready`. For a code
rollback revert the PR. `glovo_handoff_refs` and `glovo_rate_counters` hold
synthetic data only and can stay, or be dropped by the migration role once empty.
