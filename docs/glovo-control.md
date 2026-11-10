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
`min(900s, time left until the approval's fresh_until)`; the 120 s reserve
margin is enforced by the receipt reservation. Lock order: tenant, owner, live
connection read, order, approval receipt, bridge commands; a lock timeout is
`tenant_busy`. Cancel and read outcomes are a total table over command status
and effect state; a pair outside it is 503 `unavailable` with rollback.

## Runtime role

The fence, audit and sweeper run on the shared `glovo_runtime` pool. The bridge
schema is applied by `bridge.ApplySchema` with the runtime role granted exactly
what it needs, and `bridge.NewRuntimeStore` enables wire versions. The
one-database proof (`control.ProveOneDatabase`) refuses a second database, a
standby, an owning runtime role and a trigger on the bridge relations.

## Write fence

`SetFence` is called only when all six hold: the gate is open, hold
mctl-gitops#2457 is lifted, the one-database proof passed, the #959 revocation
hook is installed, `MembershipRevocationWired()` is true, and `receipt.Ready`
passes. Until then the bridge keeps its refusing fence. A fence refusal of
`cancel_order_fake` is `approval_invalid`.
