# Tenant roles: which writes need which role

Decisions for mctl-api#489, building on the gate from #478 / #487
(`internal/api/tenant_role.go`).

## Authorization modes

- `TENANT_AUTHZ_MODE=principal` is the current mode. The role is read by the
  caller's `prn_` principal from `members[].principalId` and `role`. A GitHub,
  ZITADEL or other OIDC human is decided the same way.
- `legacy` and `shadow` are rollback modes. The role is keyed on a
  GitHub-proven login; a Dex or generic OIDC human holds no tenant role and is
  refused on role-gated writes. Shadow also records the principal comparison.

If the role cannot be read, the answer is 503 (`tenant_role_unavailable` on
work-item routes) and nothing is written.

## Roles

- `viewer`: passes no write.
- `developer`: ordinary writes, work items, execution requests, repo sync,
  incidents.
- `owner`: destructive, high-risk and commerce writes.

Operation minimums are in `internal/operations/registry.go`.

## Gated routes

| Route | Minimum |
|---|---|
| `POST /api/v1/work-items` (private items included) | developer |
| `PATCH /api/v1/work-items/{id}` | developer |
| `POST /api/v1/work-items/{id}/intents` | developer |
| `POST /api/v1/work-items/{id}/executions` | developer |
| `POST /api/v1/work-items/{id}/surface-refs` | developer |
| `POST /api/v1/work-items/{id}/resume` | developer |
| `POST /api/v1/work-items/{id}/execution-requests` | developer |
| `POST /api/v1/repos/sync` | developer |

Item routes check visibility first, so a caller who cannot see an item gets 404
`work_item_not_found`, never a role refusal. A refusal is 403
`tenant_role_forbidden` with a `denied` audit entry.

## Writes with no tenant role gate, and why

- Action-approval decisions: human platform admin only (#571). A tenant
  `owner` cannot approve.
- Human-input responses: authorized by the request's `actor_refs`.
- Surface identities and surface principals: per-principal identity binding,
  unrelated to tenants.
- Snapshot sealing and execution-request claim/fulfil/reject: service
  principal only, which is stricter than `developer`.
- Reads: never role-gated. Tenant membership (and work-item visibility) is the
  only read check.

## Machine callers

The decision follows the principal, not a GitHub login. The service principal
is a platform admin and passes. An agent token acting for no human holds no
tenant groups; if one ever carried a non-admin tenant scope it would be refused
as a non-human caller. A delegated or relayed request is decided as the human
principal it names.

## Repo sync and the portal

mctl-api requires `developer` for `POST /repos/sync`. The portal plugin
(`/api/github-app-connect/repos/sync`) still allows `viewer`; a companion
portal issue to raise it to `developer` must be opened and linked here.
