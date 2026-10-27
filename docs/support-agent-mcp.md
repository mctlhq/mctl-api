# Support agent over MCP

Two MCP tools make the tenant support agent (`mctl-support`, A2A 1.0 over the
HTTP+JSON binding) reachable from every MCP client (mctl-api#814).

- `mctl_ask_support(tenant, question, context_id?)` creates a support task and
  waits for the answer. It is not read-only: it spends the tenant's model budget.
- `mctl_get_support_task(id)` reads a task, to collect an answer that took
  longer than the wait. Read-only.

## Authority

The caller's own bearer is forwarded unchanged. mctl-api adds no authority and
uses no service credential. Its only check is that the caller may act on the
tenant (`HasTenantAccess`; in stdio mode `/api/v1/whoami`); mctl-support then
applies its own check. Platform admins pass the mctl-api check for any tenant.
Redirects are never followed, so the bearer cannot reach another host.

A scoped agent run token (for example the `support` scope) cannot call
`mctl_ask_support`: neither tool is in `supportTools`. `mctl_ask_support` is in
the receipt-gated set (policy `mctl-api/agent-receipt-gate/v2`).

## Waiting

The send uses `configuration.returnImmediately: true`, so the task id arrives
at once. One budget, `SUPPORT_ASK_WAIT`, covers the send and all polling and is
never extended. If the task is not finished in time and its last read
succeeded (the send reply counts when no poll was due), the result is
non-error with `terminal: false` and the task id: continue with
`mctl_get_support_task`. If the last poll failed, it is a tool error that
still names the task id.

If the send fails without a task id (transport error, budget or request
deadline expiry, 5xx or an undecodable reply) the tool returns `support_send_outcome_unknown` naming the
`messageId`. It does not poll and never resends: a task may exist.

## Answer

For a COMPLETED task the answer is read from `status.message.parts`; the
artifacts are read only when `status.message` holds no non-blank text and no
object data part; the two are never mixed and `history` is never read. `text`
is the non-blank text parts joined with a newline; `result` is the first object
data part, unchanged. A COMPLETED task with no answer is the tool error
`support_empty_answer`. FAILED, REJECTED and CANCELED are tool errors with the
reason. INPUT_REQUIRED and AUTH_REQUIRED return the state and reason.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SUPPORT_A2A_URL` | unset | Base URL, absolute; https unless loopback. Unset: both tools answer "not configured". |
| `SUPPORT_ASK_WAIT` | `60s` | Single wait budget, 5s to 90s. |
| `SUPPORT_POLL_INTERVAL` | `2s` | Poll spacing, at least 500ms. |
| `SUPPORT_REQUEST_TIMEOUT` | `15s` | Cap on one `GET /tasks/{id}`, 1s to `SUPPORT_ASK_WAIT`. |

When configured, `POST /mcp` gets both a request timeout and a write deadline
of `SUPPORT_ASK_WAIT + 15s` instead of the 30s defaults; every other route keeps
30s. Unconfigured, nothing changes.
