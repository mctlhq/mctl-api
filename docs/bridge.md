# Command bridge (mctl-api#962)

The bridge passes work from the trusted `mctl-assistants` control orchestration
(inside mctl-api) to a low-trust provider worker, without giving the provider
any Temporal credential. It is a Postgres command outbox, a machine-authenticated
claim endpoint with short leases, and an exactly-once, fenced result callback.

**Status: dark.** `MCTL_BRIDGE_ENABLED` is unset by default, so every route
answers 404 and the dispatcher does not start. No provider credential is issued
by this change, and the default write fence refuses every permit. The provider
is fake-only: no real Glovo API, order, checkout or payment is in scope.

## Wire contract

Command and result documents are the **unchanged** v1alpha1 schemas from
mctl-agents PR #1045 (merge `14645f93fd4eb425a3ac5adeae497209431b8342`),
vendored byte for byte in `internal/bridge/schema/` with `PROVENANCE`.
`TestVendoredSchemasMatchProvenance` pins their SHA-256. To change the wire,
change mctl-agents#1044, mctl-telegram#1236 and mctl-api#957 together first.

| Layer | Content |
|---|---|
| Outward command | strict v1alpha1 projection plus the opaque `lease_token` (`lt_...`) and the required command `nonce` |
| Outward result | `schema_version`, `command_id`, `execution_id`, `lease_token`, `attempt`, `worker_identity`, `outcome`, `provider_effect`, `completed_at`, optional `result_ref`, `error_code`, `error_detail`; `additionalProperties: false` |
| Private (Postgres only) | operation key, sequence, tenant, owner, install revision, workflow and run ids, `lease_id`, `lease_epoch`, private `lease_nonce`, result digest |

The command `nonce` is a server-generated field of the outward envelope; the
private `lease_nonce` is never sent. The result body carries no epoch, nonce,
tenant, operation key, approval or workflow id: all of those are read from the
stored row.

## Routes

All are `POST`, provider principal only, and return 404 when disabled.

| Route | Purpose |
|---|---|
| `/api/v1/bridge/commands/claim` | lease up to N due commands of the caller's provider; body optional `{"max": n}` |
| `/api/v1/bridge/commands/{command_id}/result` | submit a v1alpha1 result, exactly once |
| `/api/v1/bridge/commands/{command_id}/write-permit` | ask for a single-use permit for one synthetic mutation; body `{"lease_token": "lt_..."}` (private model, not part of v1alpha1) |

## States

Command `status`: `pending`, `leased`, `completed`, `cancelled`, `expired`.
Internal `effect_state`: `none`, `permitted`, `succeeded`, `failed`,
`not_performed`, `unknown`. `not_performed` is internal; it is not a
v1alpha1 `outcome` (a refused approval is `outcome=approval_refused` with
`provider_effect=none`).

- A lease expiry reclaims the command under `lease_epoch+1` with a new token and
  a rotated private nonce; the old holder gets `lease_stale`.
- A command past `expires_at` becomes `expired`; a permitted effect becomes `unknown`.
  Besides the lazy expiry in `Claim` (scoped to the claiming provider's
  tenants), a background sweep (`Expirer`, actor `system:expiry-sweep`) runs
  whenever the bridge is enabled, independent of provider polls and of
  `TEMPORAL_ADDRESS`. Interval 30s (override `MCTL_BRIDGE_EXPIRY_SWEEP_INTERVAL`),
  100 rows per batch, a finite number of batches per tick, rows locked by
  another transaction skipped (`FOR UPDATE SKIP LOCKED`). Under a large backlog,
  long locks or database failures there is no one-interval guarantee.
  When the bridge is enabled, `/metrics` exposes
  `mctl_api_bridge_expiry_processed_total`,
  `mctl_api_bridge_expiry_sweep_errors_total`,
  `mctl_api_bridge_expiry_consecutive_errors`,
  `mctl_api_bridge_expiry_backlog`,
  `mctl_api_bridge_expiry_oldest_overdue_seconds` and
  `mctl_api_bridge_expiry_last_success_timestamp_seconds`. The values are
  process-local (reset at restart), with no command or tenant labels.
  A failed backlog query counts as an error and does **not** advance the last
  success timestamp; normal shutdown cancellation is not an error. Warning
  logs flag overdue age over 300 seconds or three consecutive failures.
  Install corresponding Prometheus alerts **before activation**: sustained
  `mctl_api_bridge_expiry_oldest_overdue_seconds > 300` for 5m,
  `mctl_api_bridge_expiry_consecutive_errors >= 3` for 2m, and
  `time() - mctl_api_bridge_expiry_last_success_timestamp_seconds > 120`
  for 5m, scoped to bridge-enabled targets. These are **recommended alert
  thresholds, not a claim that PrometheusRule is already deployed**;
  installation and alert delivery verification are a separate release gate.
- Transition rows record the status the command had under the row lock as
  `from_status` (`pending -> leased` for a first lease, `leased -> leased` for a
  reclaim, `pending|leased -> expired` for expiry).
- The stored `result` never contains `lease_token`; `result_digest` is
  unchanged (it still covers the full parsed result). `ReadOutcome` strips
  `lease_token` from rows written before this change. Historical rows are
  cleaned by the operator-invoked, bounded `Store.ScrubLegacyResultBatch`,
  never at startup. The **explicitly gated maintenance CLI** below provides
  a runnable entry point. The plaintext `bridge_commands.lease_token` column
  is not changed here: a separate security decision (including backup
  retention) is required before the first provider credential is issued
  (mctl-gitops#2457).

- Commands of one execution are claimable in `sequence` order.
- Result CAS: `status='leased'` and the stored epoch and private nonce. The
  signal-outbox row is inserted in the same transaction.
- Replay of the same server-computed digest returns `replayed: true`; a
  different digest after completion is `result_conflict`.

### Operator-only legacy JSONB scrub (activation prerequisite)

Run only under a separately approved maintenance change and limited DB
credentials, after confirming old writers cannot reintroduce token-bearing
results. The schema and indexes must already be migrated: this CLI uses
`OpenExistingStore` to confirm the table exists and **does not execute DDL**. **Never** invoke from API startup or a deployment hook. Supply the
database URL through a scoped secret named
`MCTL_BRIDGE_SCRUB_DATABASE_URL` (not command-line arguments) and keep it
out of logs and version control:

```sh
# Within an approved maintenance job whose environment securely contains
# MCTL_BRIDGE_SCRUB_DATABASE_URL (do not paste the URL into shell history):
go run ./cmd/bridge-scrub --confirm=scrub-legacy-results --batch-size=100 --max-batches=100
```

Every batch executes in a short (at most 30s) transaction using `FOR UPDATE
SKIP LOCKED`, prints the count changed and exact remaining token-bearing
JSONB rows, and is safe to repeat after interruption. The command has a
10-minute outer limit, finite batch cap, and **nonzero exit** for DB errors,
no progress due to locks, cancellation, or remaining rows. When the limit is
reached, repeat the same approved command after assessing contention. The
`remaining` query is an exact full-table scan after *each* committed batch;
avoid high-frequency execution on a large table and budget DB I/O/WAL. A
reported zero is a point-in-time result only: verify no old writer is active
and independently query `SELECT count(*) FROM bridge_commands WHERE result
? 'lease_token'` on the target DB before changing the activation hold. The
scrub **does not** erase plaintext `bridge_commands.lease_token` nor any
previous backup, audit/log export or snapshot. These retain separate
security-owner and data-retention decisions.
## Error codes

| Code | HTTP |
|---|---|
| `invalid_document`, `invalid_input` | 400 |
| `command_not_found` (also for a foreign provider or tenant) | 404 |
| `lease_stale`, `binding_mismatch`, `command_cancelled`, `command_expired`, `result_conflict`, `already_completed`, `not_mutating`, `permit_already_issued` | 409 |
| `result_inconsistent` | 422 |
| `write_fence_refused` | 403 |
| `write_fence_unavailable` | 503 |
| `bridge_provider_gate`, `bridge_provider_required` | 403 |
| `bridge_unavailable` | 503 |
| `bridge_internal` | 500 |

Every refusal rolls its transaction back: no row, outbox entry or permit changes.

## Authentication

A bridge provider is `service:bridge-provider:<ref>`, holding only
`bridge:provide`. It is confined to the bridge routes by `bridgeProviderGate`
and refused on every other route (DevLoop, work items, operations). Which
tenants it may touch is an upper bound from `MCTL_BRIDGE_PROVIDERS`
(`[{"ref","issuer","subject","audience":"mctl-api-bridge","tenants":[...]}]`);
the tenant and owner of a command come from its stored row.

`BridgeProviderConfig.PinClaims` is the exact `iss`/`aud`/`sub`/`exp`/`nbf` pin
for a federated service OIDC token. The verifier that feeds it is **not wired**:
choosing the issuer is gated on mctl-gitops#2506 and must not silently pick
ZITADEL or Vault. Until then the only way to authenticate is the static
`MCTL_BRIDGE_PROVIDER_TOKENS` (`ref=token` lines), **for tests only**.

## Write fence

`WriteFence` is the transaction-compatible interface to mctl-api#954. The default
refuses with `write_fence_unavailable` and issues zero permits. A permit alone
never proves exactly-once provider I/O: the provider must dedupe by command and
read back, and an ambiguous outcome stays `unknown` and is never retried.
`hir_` is never approval.

## Signals

A dispatcher drains `bridge_signal_outbox` and sends the `bridge-result` signal
(`command_id`, `result_digest`) to the stored workflow and run only. Delivery is
at least once; the workflow dedupes on `command_id`. A Temporal NotFound ends as
`unknown`. It starts only when the bridge is enabled and `TEMPORAL_ADDRESS` is set.

## Deployment gates

Not to be enabled before: mctl-gitops#2456 and #2469 (Temporal frontend auth),
the mctl-gitops#2506 issuer decision, mctl-gitops#2457 (P1 deployment and P2 OAuth
approvals), and independent security approval of any credential issuance.

## Rollback

Unset `MCTL_BRIDGE_ENABLED` (routes 404, dispatcher stops), remove
`MCTL_BRIDGE_PROVIDERS`, and mark open commands `cancelled`. The additive tables
may stay, or be dropped once empty: `DROP TABLE bridge_write_permits,
bridge_signal_outbox, bridge_command_transitions, bridge_commands`.
