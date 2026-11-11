# Glovo join facade (mctl-api#957)

The facade side of the Glovo join: nine routes under
`/api/v1/assistants/glovo/v1alpha1` that the Glovo facade calls on behalf of
one end user. Everything is dark: nothing here turns Glovo on in production.

Contract: `glovo-facade-mctl-api/v1alpha1`, digest
`sha256:00d6a8f2ff376d1b6f86fb8a510864cb4c0fb8dc8689793768f06bae17765ec5`
(`internal/glovojoin/contract/`, mirrored in `internal/glovojoin/testdata/version-digests.json`).

## Routes

| Method and path | Scope | Purpose |
| --- | --- | --- |
| `POST /resolve` | any Glovo scope | issues the `scope_ref` of the subject |
| `GET /connection` | `glovo:read` | connection state |
| `POST /connections` | `glovo:basket:prepare` | starts a connection; replay gives a fresh `handoff_url` |
| `POST /orders:list` | `glovo:read` | order history |
| `POST /previews` | `glovo:read` | preview of a reorder |
| `GET /basket` | `glovo:read` | provider basket |
| `POST /orders:prepare` | `glovo:basket:prepare` | one transaction: preview claim, execution, approval, control start |
| `GET /orders/{order_id}` | `glovo:read` | order status |
| `GET /compatibility` | facade identity only | contract, digest and readiness |

Every route except `/compatibility` needs the subject token (`X-Mctl-Subject-Token`)
and, except `/resolve`, a `X-Mctl-Scope-Ref`. Both writes need an `Idempotency-Key`
header equal to the body key. Errors are `{"error": <wire>, "error_description": <fixed text>}`
mapped through the contract's code table; an unmapped code is 503 `dependency_unavailable`.

## Dark by construction

1. The routes are unmounted (404, even for the facade principal) unless
   `GLOVO_JOIN_ENABLED=true` and `MCTL_GLOVO_FACADE_TOKEN` is configured.
2. Even then `main` wires no dependency yet: every route that needs one answers
   503 `not_ready`, and `/compatibility` reports `deploy_ready: false`.
3. The facade principal reaches this prefix and nothing else; every other
   principal on the prefix is 401 (`glovoJoinGate`).
4. The global 300/min limiter is skipped for the facade principal (one id stands
   for every end user); the routes enforce 60/min per subject, 10 writes/min per
   subject and 600/min aggregate instead.

## Compatibility matrix

| Dependency | State in this change |
| --- | --- |
| #959-#961 connection registry and connect | used through `connect.Service` and `glovo.Store` |
| #962/#986 read bridge | `ReadBridge` interface; a double in tests; not wired in `main` |
| #985 control start | rows in `glovo.control_starts`; the dispatcher only starts from the stored row |
| #1044 control-input schema | not vendored: provisional `glovo-control-input/v1alpha1`, empty `limits` (OPEN-957-11) |
| control and provider worker heartbeats | no source in `main`: probes unwired, `not_ready` |
| facade token and roles in Vault, Helm env, gitops A15 | separate mctl-gitops deliverable |

`/compatibility` is never `deploy_ready` from this repository alone: an
unobserved heartbeat is `not_ready`, never ready.
