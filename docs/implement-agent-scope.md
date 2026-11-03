# Implement agent run scope

The `implement` agent scope (`internal/auth/agent_scope.go`) lets the
`implementer` agent (workflow `mctl-agents-implement`) call mctl-api with its
per-run token instead of the static service token
(mctlhq/mctl-agents#717 S5). The pod trades its projected ServiceAccount
token at `POST /api/v1/agent-run-tokens/exchange`; the template table in
`cmd/api/main.go` maps `mctl-agents-implement` to agent `implementer` and
scope `implement`.

## Execution-bound

Unlike `mctl-agents-investigate`, the implement template does **not** set
`AllowWithoutExecution`: a run submitted without an `execution_id` parameter
is refused at the exchange (`workflow_without_execution`). Its approvals are
always one execution's (S4), so a token bound to no execution could not use
them anyway.

## Routes

| Route | Why |
|---|---|
| `/mcp` (POST, GET, DELETE) | MCP transport; tools are limited to reads (`IsReadTool`), no governed tool |
| platform GETs shared with `investigate` | the REST calls behind the read-only MCP tools |
| `GET /api/v1/work-items/{own}/...` | its own work item, read only (never `/intents`) |
| `POST /api/v1/action-approvals` | request an approval for its own execution |
| `GET /api/v1/action-approvals/{id}` | read an approval of its own execution, or that execution's DevLoop grant |
| `POST /api/v1/action-approvals/{id}/consume` | spend its own approval |
| `POST /api/v1/action-approvals/{id}/execute` | mark its own approval, or the execution's DevLoop grant, executed |

The approval routes carry no execution in their path. The handlers hold an
agent run to the approvals of the execution its token is bound to (S4), so
the scope is only as strong as that binding. `execute` is listed by this
scope and no other (`TestOnlyImplementScopeListsApprovalWrites`): any scoped
run on an execution whose scope lists it can mark that execution's grant
executed.

Not listed: `.../decision` (a human's), the approval list, every other
write, and the `/api/v1/lifecycle/claims/*` routes (they do not exist in
mctl-api yet; a scope that is to use them must list them when they ship).
