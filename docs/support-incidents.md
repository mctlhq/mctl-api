# Support incidents (mctl-api#830)

mctl-support files incidents for the tenant of its current task with a
dedicated principal, `service:mctl-support-incidents`, authenticated by
`MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN`.

## Principal

- Not an admin, no groups, no tenant access, no named permission.
- Token at least 32 characters. A token equal to the agent service token, a
  surface, usage-writer, evidence-writer, registry-publisher or
  security-provider token disables both principals (ERROR log naming the env).
- Unset: the principal does not exist.

## Confinement

- Only `POST /api/v1/incidents`; every other route, including `/mcp`, answers
  403 `support_incident_producer_route_not_allowed`.
- `source` must be `support` (403 `support_incident_source_not_allowed`).
- `type` must be `platform_defect`, `quota_request`, `policy_exception` or
  `needs_owner` (403 `support_incident_type_not_allowed`).
- `fingerprint` must start with `support:` (400 otherwise).
- The tenant comes from the body; no tenant access or role check applies.
  Status is forced to `open` and triage fields are ignored.
- Every create (or dedup hit) writes one `incident-create` audit row; refusals
  on source or type write a `denied` row. Summary and evidence are not audited.
- Dedup on `(tenant, fingerprint)` is unchanged.

## Aggregation

`GET /api/v1/incidents/support/aggregation` (admin only) returns
`{"items": [{"fingerprint", "type", "affected_tenants", "count"}], "count": n}`
for open `source=support` incidents grouped by `(fingerprint, type)`, ordered
by count descending then fingerprint. 503 when the alert store is not
configured.
