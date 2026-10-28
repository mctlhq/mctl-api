# Support agent over MCP

Two MCP tools make the tenant support agent (`mctl-support`, A2A 1.0 over the
HTTP+JSON binding) reachable from every MCP client (mctl-api#814).

- `mctl_ask_support(tenant, question, context_id?)` creates a support task and
  waits for the answer. It is not read-only: it spends the tenant's model budget.
- `mctl_get_support_task(id)` reads a task, to collect an answer that took
  longer than the wait. Read-only.

## Authority

The caller's own API token is never sent to mctl-support. For each tool call
mctl-api mints one short-lived access token for the caller's principal, with
`aud` set to `OAUTH_SUPPORT_RESOURCE`, no `groups`, no refresh token and a
random `jti`, and sends only that token. It is valid only on the four routes
mctl-support relays (a support-audience token gets 401 on `/mcp`), is never
persisted, and is never logged or returned. `mctl_ask_support` uses
`SUPPORT_TOKEN_TTL` (the token must outlive the whole support task);
`mctl_get_support_task` uses at most `SUPPORT_REQUEST_TIMEOUT + 60s`, capped at
5m. Each mint writes one audit row, `support.token_mint`, with the principal,
tenant, tool, `jti`, `aud` and `exp`. Metric: `mctl_support_token_mints_total{result}`.

mctl-api adds no authority and uses no service credential. Its only check is
that the caller may act on the tenant (`HasTenantAccess`); mctl-support then
applies its own check. Platform admins pass the mctl-api check for any tenant.
Redirects are never followed, so the token cannot reach another host.

## Failure modes

The tools fail closed and never fall back to forwarding the API token:

- `support_audience_not_configured`: `OAUTH_SUPPORT_RESOURCE` is empty.
- `support_token_unavailable`: no minter or auditor is wired (stdio mode, or no
  OAuth server), no user is in the request context, or the mint failed (for
  example, the caller's principal could not be read).
- `support_token_refused`: the caller is an agent run principal, a service or
  surface principal, a relayed request, has no resolved principal, or its
  principal is disabled or does not exist.

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
| `SUPPORT_TOKEN_TTL` | `11m` | Lifetime of the token minted for `mctl_ask_support`, 2m to 15m. Covers mctl-support's 600s task ceiling plus 60s. |

When configured, `POST /mcp` gets both a request timeout and a write deadline
of `SUPPORT_ASK_WAIT + 15s` instead of the 30s defaults; every other route keeps
30s. Unconfigured, nothing changes.
