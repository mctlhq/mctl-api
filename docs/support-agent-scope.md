# Support agent run scope

The `support` agent scope (`internal/auth/agent_scope.go`) gives a run token
read access to exactly one tenant. Unlike `investigate` (`ReadAllTenants`),
it is tenant-bound: the tenant is stored on the `agent_run_tokens` row and
every check compares against it.

## Minting

`POST /api/v1/agent-run-tokens` with scope `support` is minted by a human
(directly or relayed by a registered surface), not by the service principal,
an agent token or a delegated agent request.

```json
{"agent": "mctl-support", "execution_id": "we_...", "scope": "support", "tenant": "namax66"}
```

- Tenant member: allowed when the caller's groups include `tenant`.
- Platform admin: allowed for any existing tenant; the mint audit entry
  records `admin_override=true`. The token is still bound to that tenant.
- Default TTL 10 minutes, maximum 1 hour.
- The caller principal is stored as `via_principal_id` and returned by
  `User.AgentRunRequestedBy()`.

Refusals: 400 `agent_scope_tenant_required`, 400
`agent_scope_tenant_unexpected` (tenant given for a scope that is not
tenant-bound), 404 `tenant_not_found`, 403 `agent_scope_tenant_forbidden`,
403 `agent_run_token_requester_forbidden`, 400 `invalid_ttl`.

## Enforcement

- REST gate: GET routes on the scope's list only; every tenant path segment
  must equal the bound tenant; `team`, `tenant`, `team_name` and `namespace`
  query parameters must equal it and appear once; list routes must carry the
  tenant filter. Denials return 403 `agent_scope_denied`.
- MCP: only the support tool list; `team`, `team_name` and `tenant`
  arguments must equal the bound tenant, and tenant-taking tools must carry it.
- `User.HasTenantAccess(t)` is true only for the bound tenant.
