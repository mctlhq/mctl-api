# Orchestrator DevLoop principal

`service:mctl-orchestrator-devloop` (mctl-api#963) lets the Codex orchestrator
on the Mac mini start a DevLoop for an issue it has triaged, and read that loop
back, without a human relaying the start. It cannot approve a proposal: that
stays a human admin's decision (#571).

## Authentication

The principal is a ZITADEL machine user, verified by the existing federated
OIDC path (`MCTL_OIDC_PROVIDERS`). Its JWT-profile key stays on the mini; the
bearer the API sees is a short-lived access token. The verified
`(MCTL_ORCHESTRATOR_DEVLOOP_PROVIDER, MCTL_ORCHESTRATOR_DEVLOOP_SUBJECT)` pair
is mapped to this principal ahead of the generic OIDC user, so whatever groups
the token carries are dropped. The principal is provisioned as kind `service`;
disabling that principal refuses it like any other.

Both variables must be set. A provider naming a built-in namespace (`service`,
`github`, `github-actions`, `dev`, `dex`, `agent`, `principal`) disables the
mapping, and a customer identity is never mapped.

## What it may call

`orchestratorDevLoopGate` runs before every handler, `/mcp` included:

| Request | Answer |
|---|---|
| `POST /api/v1/agents/dev-loop/start` for a repository on `MCTL_ORCHESTRATOR_DEVLOOP_REPOS` | handled (the Temporal path) |
| the same for any other repository, or with an empty list | 403 `orchestrator_devloop_repo_not_allowed` |
| a malformed start (bad JSON, no or invalid `issue_url`) | 400, audited as `orchestrator_devloop_invalid_request` |
| `GET /api/v1/agents/dev-loop/dev-loop-mctlhq-<repo>-<n>` for an allowed repository | handled |
| the same for any other repository | 403 `orchestrator_devloop_repo_not_allowed` |
| `GET /api/v1/whoami` | handled |
| `POST /api/v1/agents/dev-loop/{id}/approve` | 403 `orchestrator_devloop_approve_forbidden` |
| `/api/v1/operations/mctl-agents-investigate/...` (the `use_temporal=false` path) | 403 `orchestrator_devloop_temporal_required` |
| anything else, `/mcp` and encoded paths included | 403 `orchestrator_devloop_route_not_allowed` |

Repositories match exactly and case-sensitively: the workflow id keeps the
issue URL's case, so `mctlhq/MCTL-API` is refused rather than starting a second
loop beside `mctlhq/mctl-api`'s.

Every request writes exactly one record of its outcome. A refusal, a read and
`whoami` write an `orchestrator-devloop.request` row (`allowed` or `denied`,
with the code). An admitted start writes no gate row; the handler records it:
the usual `dev-loop-start` row when it reaches Temporal, or a `denied`
`orchestrator-devloop.request` row when it is refused or malformed.

## Receipt gate

The agent receipt gate (mctl-api#723) guards governed MCP tool calls of agent
principals. This principal is not an agent and never reaches `/mcp`, so the
receipt gate does not apply to it; the route gate above is the whole decision,
and `TestOrchestratorDevLoop_GateRefusals` pins `/mcp` as refused.
