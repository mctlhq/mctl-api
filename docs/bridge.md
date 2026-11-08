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
- Commands of one execution are claimable in `sequence` order.
- Result CAS: `status='leased'` and the stored epoch and private nonce. The
  signal-outbox row is inserted in the same transaction.
- Replay of the same server-computed digest returns `replayed: true`; a
  different digest after completion is `result_conflict`.

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
choosing the issuer is gated on mctl-api#2506 and must not silently pick
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
the #2506 issuer decision, mctl-gitops#2457 (P1 deployment and P2 OAuth
approvals), and independent security approval of any credential issuance.

## Rollback

Unset `MCTL_BRIDGE_ENABLED` (routes 404, dispatcher stops), remove
`MCTL_BRIDGE_PROVIDERS`, and mark open commands `cancelled`. The additive tables
may stay, or be dropped once empty: `DROP TABLE bridge_write_permits,
bridge_signal_outbox, bridge_command_transitions, bridge_commands`.
