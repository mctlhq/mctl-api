# Glovo control dispatch (mctl-api#985)

Internal routes that let the control worker dispatch or cancel one Glovo order
and read the resulting command and approval. Everything is dark: nothing here
turns Glovo on in production.

## Routes

All under `/api/v1/internal/glovo`, reachable only by the principal
`service:glovo-control-worker` (permission `glovo:control-dispatch`, audience
`mctl-api-glovo-control`). Every other caller gets 403 `not_authorized` on these
routes, and the control worker gets 403 on every other route.

| Method and path | Purpose |
| --- | --- |
| `POST /orders/{order_ref}/dispatch` | body `approval_ref`, `fingerprint`; enqueues the one mutating bridge command |
| `POST /orders/{order_ref}/cancel` | cancels before dispatch or marks the order `unknown` |
| `GET /commands/{command_id}` | command status and effect state |
| `GET /approvals/{approval_ref}` | approval state |

Request and response bodies, the `Idempotent-Replayed` header and every refusal
of the closed code set are recorded in `internal/glovo/control/contract/`, with
`SHA256SUMS`. `UPDATE_CONTRACT=1 go test ./internal/api -run TestControlContract`
regenerates them after a deliberate change.

## Dark by construction

1. The build gate `glovo.ControlDefault.Open` is a const, false in every release
   build. The `glovojoin_fixture` build tag opens it for tests only.
2. `MCTL_GLOVO_CONTROL_ENABLED=true` must also be set, with
   `MCTL_GLOVO_CONTROL_WORKER` carrying the server-side tenant bound.
3. No production verifier mints the principal until mctl-gitops#2506.
4. No dispatcher is attached in `main` yet, so a mounted route answers 503
   `not_ready`. A failed or unobserved readiness check is `not_ready`, never
   ready.

## Dispatch

Replay is answered first (same approval, same command: 200 with
`Idempotent-Replayed: true`). The command TTL is
`min(900s, floor of the time left until the approval's fresh_until)`. A receipt
whose `fresh_until` is 120 s (`workitems.ReservePermitMargin`) or less away is
refused as `approval_expired` before the command is enqueued, so no command row
exists that the permit reservation would later refuse. The live membership read
taken under the row locks is bounded (`glovo.BoundedMembership`, 2 s, shorter
than the 5 s lock timeout); a timeout is `unavailable`, never "not a member".
Lock order, the same in
dispatch, cancel and the permit path: tenant (L1, shared), owner (L2, shared for
dispatch and the permit, exclusive for revoke, reconnect and activate), the
order row (L3), the approval receipt (L4), then the live-connection read and
the bridge command rows (L5). The permit takes L2, L3 and L4 in the fence's
`PreLock` before it locks the command row, so a revoker holding L2 exclusive
can never wait for a row that a permit holds while the permit waits for L2.
A lock timeout is `tenant_busy`. Cancel and read outcomes are a total table over command status
and effect state; a pair outside it is 503 `unavailable` with rollback.

## Runtime role

The fence, audit and sweeper run on the shared `glovo_runtime` pool. The bridge
schema is applied by `bridge.ApplySchema` with the runtime role granted exactly
what it needs, and `bridge.NewRuntimeStore` enables wire versions. The
one-database proof (`control.ProveOneDatabase`) refuses a second database, a
standby, an owning runtime role and a DISABLED trigger on the bridge, glovo or
approval relations (a guard that is switched off is a silently open table; enabled guard
triggers are the normal state and pass).

### Bridge store at startup

The mode is decided once, from `to_regclass('public.bridge_schema_version')`
(`bridge.SchemaMigrated`):

| Probe | `GLOVO_DB_URL` pool | Result |
| --- | --- | --- |
| row exists | present | `bridge.NewRuntimeStore` on that pool (checks the version, the read level and the runtime grants, then enables wire versions) |
| row exists | absent | not_ready (`bridge_schema_migrated_glovo_db_url_unset`); never the legacy store |
| row absent | any | legacy `bridge.NewStore` (does not enable wire versions) |
| the probe fails | any | not_ready (`bridge_mode_probe_failed`); a failed read is never "not migrated" |

`NewRuntimeStore` is the only caller of `EnableWireVersions`. A missing
`GLOVO_DB_URL` or `WORK_ITEMS_DB_URL` leaves the dispatcher unattached
(`not_ready`).

### Revocation hook

The real hook, `bridge.CancelOpenForConnections`, runs `SELECT ... FOR UPDATE`
on `bridge_commands` inside every connection-ending transaction, and an error
there rolls the whole end back. It is therefore installed only when
`MCTL_GLOVO_CONTROL_ENABLED=true` AND the build gate is open AND a boot-time
proof (`bridge.SchemaMigrated` plus `bridge.VerifyRuntimeGrants` on the
`GLOVO_DB_URL` pool) shows the table and the runtime grants. With the flag and
the gate on and the proof failing, the binary refuses to boot; it never falls
back to the synthetic hook. With the flag off or the gate closed (every release
build) the proof is not run and the #959 lifecycle is exactly as before: the
synthetic no-op hook. The synthetic hook never satisfies the write-fence
condition, so a Glovo-enabled build with control disabled keeps the refusing
fence.

### Lock order of row locks

`CancelOpenForConnections` locks the open commands `ORDER BY command_id COLLATE
"C"`: one byte order, independent of the database collation, for every taker of
these row locks.

## Write fence

`SetFence` is called only when all six hold: the gate is open, hold
mctl-gitops#2457 is lifted, the one-database proof passed, the installed
revocation hook IS `bridge.CancelOpenForConnections` (checked by function
identity, `Store.RevocationHookIs`, not merely non-nil), `MembershipRevocationWired()`
is true, and `receipt.Ready` passes. The hook is installed as described under
"Revocation hook", so the synthetic no-op hook can never satisfy the condition.

`MembershipRevocationWired()` needs a positive signal: a probe installed with
`WithMembershipRevocationProbe` (a detector heartbeat or an end-to-end proof)
that returns true. A label alone (`WithMembershipRevoker`), no probe, a nil
store or a panicking probe answer false, the interim state named `refusing`.
The only caller is one installer in `cmd/api/main.go`
(`installWriteFence`); it calls `SetFence` only when all six hold, and a test
fails if it installs with any one of them false. The hold field is a constant
that is false in this change (OPEN-985-11), so the installer never installs.
Until all six hold the bridge keeps its refusing fence. A fence refusal of
`cancel_order_fake` is `approval_invalid`.

## Interface pins

`internal/glovo/control/pins.go` asserts at compile time that `orders.Store`,
`workitems.Store`, `glovo.Store`, `bridge.Store` and `glovojoin.ControlStartTx`
satisfy the interfaces the dispatcher declares, so a signature drift in one
package fails the build rather than a nil-check at runtime. The principal check
requires `IsGlovoControlWorker`, not just the permission: an agent minted with
`glovo:control-dispatch` is refused.
