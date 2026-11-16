# Decision context and authority contract for action approvals

mctl-api#700, mapping the findings of mctl-api#182. An action approval (`aar_`)
authorizes one hashed side effect. This contract says what a human reviewer is
shown, what the decision is bound to, what authority is recorded, and what is
checked again just before the side effect. The rules live in
`internal/governance`.

Stored authority claims are evidence, never authorization. Authority is still
`ADMIN_PRINCIPALS` plus the principal store's human check; policy identity is
still `policy_rule_id`/`policy_version`.

## Mandatory decision context

`GET /api/v1/action-approvals/{id}` (and each list entry) returns
`decision_context`. The context is checked twice:

- **At create.** `POST /api/v1/action-approvals` fills what the registry and
  the registered policy supply, then refuses with 422
  `approval_context_incomplete` (`details.missing_fields`) if `risk_level`,
  `side_effect`, `policy.decision` or `policy.reasons` is still empty. Nothing
  is stored, so the same idempotency key with the context supplied is a fresh
  create. A client creating an approval under a rule that is not in
  `governance.Policies`, or for an `action_kind` that is not registered, must
  send these fields itself.
- **At approve.** An `approve` is refused with 422 `approval_context_incomplete`
  (`details.missing_fields`, request stays pending) unless all of these are
  present. This covers rows created before the create-time check. A `deny` is
  never gated.

| Field | Source |
|---|---|
| `target`, `args_digest`, `intent_hash` | the intent |
| `risk_level` | operation registry for a registered `action_kind`, else the request. A contradicting request value is 400 `approval_context_invalid` |
| `side_effect` | request, else the registered policy |
| `intent_source` | request, else `work_item:<wi_>`, else `execution:<we_>` |
| `policy.rule_id`, `policy.version` | the intent |
| `policy.decision`, `policy.reasons` | request, else the registered policy |

Also shown, not mandatory: `artifact_hash`, actor and subject principals, the
decider, `authority_basis`, `authz_mode`, and the times `created_at`,
`decided_at`, `expires_at`, `fresh_until`.

`context_digest` is sha256 over `mctl-decision-context/v1\n` and one
`<field>:<byte length>:<value>\n` line per field, in this order: `intent_hash`,
`target`, `args_digest`, `artifact_hash`, `risk_level`, `side_effect`,
`intent_source`, `policy_rule_id`, `policy_version`, `policy_decision`,
`policy_reasons` (joined by `,`). The result is `sha256:<hex>`. `intent_hash`
itself is unchanged.

A decision may send `context_digest`; a value that differs from the current
digest is 409 `approval_context_changed` and the request stays pending.

## Decision binding (mctl-api#869)

Both direct human decision routes (`POST /api/v1/action-approvals/{id}/decision`
and `POST /api/v1/agents/dev-loop/{workflow_id}/approve`) accept an optional
`binding` object `{approval_ref, context_digest, content_digest}`: the `aar_`
id, `decision_context.context_digest` and the approval `artifact_hash` the
person was shown. When present all three are required (422
`approval_binding_missing`, `details.missing_fields`). On the DevLoop route
only the grant named by `approval_ref` is decided, never the execution's
newest: a newer grant is 409 `approval_context_changed` with
`details.current_approval_ref` and `details.reapproval_required=true`. A
differing digest is the same 409 and the grant stays pending. An approved
grant with the same binding returns the existing decision.

`MCTL_APPROVAL_BINDING` migrates legacy callers: `off` (no check on absence),
`observe` (default; a decision without `binding` is accepted, audited as
`approval.binding_absent` and counted in `approval_binding_absent_total`),
`enforce` (no `binding` is 422 `approval_binding_missing`; the top-level
`context_digest` no longer substitutes). An unknown value fails startup.
Authority is unchanged: only a human admin acting directly decides.

## Privacy rule

The context holds references, digests, enums and reason codes only. It never
holds args, the free-text `reason`, or a payload. The audit log follows the
same rule.

## Captured and revalidated facts

Captured when a human approves: `decided_context_digest`, `authority_basis`
(`platform_admin`; `tenant_owner_fresh_login` for a deploy grant;
`unrecorded` on legacy rows), `authz_mode`, and
`fresh_until = min(expires_at, decided_at + ACTION_APPROVAL_MAX_DECISION_AGE)`.

Revalidated when the approval is spent (`POST .../consume`, and the
grant-authorized `mctl-agents-approve`). The approval's state is checked first:
a request that is not `approved` keeps its state refusal (`approval_not_approved`
while pending, `approval_consumed` once spent or executed, `approval_denied`,
`approval_expired`) and is never answered with an authority code. For an
approved request the facts are checked in this order, first failure wins:

1. the recomputed context digest equals `decided_context_digest` (skipped for a
   legacy row without one);
2. `fresh_until` has not passed;
3. the decider's principal is still an active human (`CheckHumanPrincipal`);
4. in `TENANT_AUTHZ_MODE=principal`, the decider is still in `ADMIN_PRINCIPALS`
   (recorded as `skipped_legacy_mode` otherwise);
5. the policy version equals the registered one. An unregistered rule passes
   unless `ACTION_APPROVAL_REQUIRE_REGISTERED_POLICY=true`.

A decision with no decider principal is refused in principal mode; in other
modes there is no principal to check and the check is skipped.

For a deploy grant (below), step 4 is instead: the decider is still a live
`owner` of the plan's tenant, read by principal from the GitOps membership. An
admin gets no pass, and outside principal mode the check is unavailable, so the
grant cannot be spent.

A refusal never spends the approval and never reaches the executor. The store's
compare-and-set also enforces `fresh_until` atomically. Authority and policy are
checked milliseconds before it; the remaining race is bounded by the facts that
need a redeploy or a principal-store transaction to change.

## Refusal codes

Callers should key on `details.reapproval_required`, not on the code text.

| Code | HTTP | `reapproval_required` | Finding |
|---|---|---|---|
| `approval_context_incomplete` (create) | 422 | n/a: nothing stored, send the missing fields | F6 |
| `approval_context_incomplete` (decide) | 422 | no grant made | F6 |
| `approval_context_incomplete` (spend) | 409 | true: an approved row, e.g. a legacy one, whose mandatory context is incomplete is never spent | #721 |
| `approval_context_invalid` (create) | 400 | n/a | F6 |
| `approval_context_changed` | 409 | true | F6 |
| `approval_binding_missing` | 422 | n/a: nothing decided, send all three binding fields | #869 |
| `approval_stale` | 409 | true | F4 |
| `approval_expired` | 409 | true | F4 |
| `approval_authority_revoked` | 409 | true | F3 |
| `approval_decider_disabled` | 409 | true | F3 |
| `approval_authority_unavailable` | 503 | false: retry, the approval is not spent | F3 |
| `approval_policy_drift` | 409 | true | F9 |
| `approval_policy_unregistered` | 422 at create, 409 at decide and spend | false at create, true at decide and spend | strict policy (`ACTION_APPROVAL_REQUIRE_REGISTERED_POLICY`) |
| `approval_policy_unavailable` | 503 | false | strict policy with no registered policy set |

## Precedence

Structural and secret validation (400) is evaluated before governance
completeness (422), in both create and decide. Terminal-state refusals keep
precedence over governance refusals at decide and spend. The binding
checks run in this order: authority (403), body (400), binding mode and shape
(422), grant named by `approval_ref` (409), terminal state, then policy,
context completeness and the digest comparison (409).

## Freshness

`expires_at` is the requester's hard bound (at most 7 days). `fresh_until` is the
decision-age bound, never later than `expires_at`. Both are checked when the
approval is spent. Set `ACTION_APPROVAL_MAX_DECISION_AGE=168h` to keep the
previous 7-day horizon.

## Mapping to mctl-api#182

| ID | Finding | Where it is handled |
|---|---|---|
| F3 | Authority loss after approval | revalidation steps 3 and 4 |
| F4 | Expiry and freshness | `fresh_until`, `expires_at`, `approval_stale`, `approval_expired` |
| F6 | Reviewer context | mandatory `decision_context`, `context_digest` binding, revalidation step 1 |
| F9 | Policy drift | revalidation step 5, one policy source in `governance.Policies` |

## Deploy grants (`deploy.apply`)

A preview apply of a stored deploy plan (`dpl_`) is authorized by a
`deploy.apply` grant, never by `confirm` (mctl-api#1026, mctlhq/.github#254).

- `POST /api/v1/deploy/plans/{id}/approval` (MCP `mctl_request_deploy_approval`)
  opens the pending grant. Any developer of the tenant may ask, an agent
  session included. The server builds the intent from the stored plan: plan id,
  plan digest, `tenant/service`, policy `deploy.apply.tenant-owner` v1. The body
  carries nothing. A repeat returns the same grant. The answer carries
  `decide_url`, the page link to give the person, or `decide_unavailable` when
  the page is not enabled.
- A live owner of the tenant decides it on the fresh sign-in page,
  `/deploy/approvals/{aar_id}`. The link grants nothing. The person signs in
  to ZITADEL in that browser with `prompt=login`, `max_age=0`, PKCE and a nonce,
  and is resolved as their own principal. Anyone who is not a live owner of
  the plan's tenant, an admin included, sees "no such approval" and nothing of
  the plan. An owner sees the plan (target, revision, preview host, plan id and
  digest, gitops commit, requester, context digest, diff). A plan the apply
  would refuse is shown but not offered. On confirm the page resolves the
  person, reads the ownership, the plan and the grant again, and decides only
  if all three still match what was shown. The page is dark unless
  `DEPLOY_APPROVAL_UI_ENABLED=true` with `DEPLOY_APPROVAL_UI_CLIENT_ID`,
  `DEPLOY_APPROVAL_UI_CLIENT_SECRET`, `SELF_URL`, principal authz mode, the
  shared OAuth flow store, the work-items and deploy-plan stores and the
  ZITADEL federation entry. No bearer
  route decides it: the generic `/decision`, `/consume`, `/execute`, reserve and
  settle paths refuse every `deploy.*` kind, for admins too. An MCP session
  carries its person's own principal, so the requester's principal is not
  refused as decider. What tells the person from their agent is the fresh
  interactive sign-in.
- `POST /api/v1/deploy/apply` (MCP `mctl_deploy_apply`) takes `plan_id` and
  `approval_id` only. It re-checks the plan (expiry, stored digest), binds the
  grant to the plan's intent hash, revalidates the decider, spends the grant
  once, and submits `preview-deploy` with the plan's preview id and gitops
  commit. `preview_id` and `gitops_ref` are refused in any execute body.
- Deployment record (mctl-api#1047). Right after the grant is spent and before
  anything is submitted, apply writes one `deploy_records` row (`dep_...`):
  the plan and its digest, revision, gitops commit, preview id and host, the
  grant and the principal who decided it, and who applied it. If that write
  fails, nothing is submitted and the spent grant is not reusable
  (`503 deploy_apply_unavailable`; request a new grant). A plan applies once:
  grants are per requester, so a second holder's apply is refused with
  `409 deploy_plan_already_applied` before their grant is spent (or, if it
  loses a race after that check, after the spend with nothing submitted), and
  a record store that cannot be read refuses with 503 before the spend.
  Status moves once, from `submitting` to `submitted` (with the workflow
  name) or to `submit_failed` only when the submit certainly created no
  workflow; an ambiguous submit error leaves it in `submitting` (outcome not
  recorded), since a guess could not be corrected later.
  `image_digest`, `argo_revision`, `health` and `health_url` are written once
  when observed; until then health reads `unknown`, which never means healthy.
  Planned and granted fields are immutable and rows are never deleted
  (database triggers). The 202 answer carries `deployment_id`.
  `GET /api/v1/deploy/deployments/{id}` (MCP `mctl_get_deployment`) takes a
  `dep_` or the applied plan's `dpl_` id; tenant members and admins only,
  anyone else gets `404 deployment_not_found`, and an unreadable store answers
  `503 deploy_record_store_unavailable`.
- Faithful or refused: `preview-deploy` renders the service's GitOps values,
  not the intent's runtime changes. A plan whose intent changes the values
  (`intent_changes_values`, compared before redaction and over the
  base-service chart defaults at the plan's gitops commit, so a value the
  chart already defaults to is not a change), or builds from a
  context other than the repository root, is refused with
  `deploy_apply_not_reproducible`.
- Agent-deploy tenants have no other way (mctl-api#1031). A tenant whose
  values set `tenant.profile: agent-deploy` is refused `deploy-service` (every
  action: onboard, deploy, update-config, scale) and `preview-deploy` on
  `POST /api/v1/operations/{name}/execute`, so `mctl_deploy_service`,
  `mctl_scale_service` and `mctl_create_preview` answer `403
  agent_deploy_requires_plan`. Admins are refused too. CI OIDC, authorized by
  its own repository binding, is the one caller that passes, and
  `rollback-service` stays allowed. The profile is read from a fresh gitops
  checkout and covers the tenant's own name and each `{tenant}-{team}`
  namespace. A profile that cannot be read (stale checkout, malformed or
  missing values that could own the namespace, two owners, an unknown profile)
  refuses with `503 agent_deploy_profile_unavailable`, never passes as
  ordinary.
- Operators: the profile read covers every tenant directory, so one values
  file under `platform-gitops/tenants/` that fails to parse makes every direct
  `deploy-service` and `preview-deploy` on the platform answer `503
  agent_deploy_profile_unavailable`, ordinary tenants included. mctl-api logs
  `agent-deploy profile unreadable; direct deploy refused` at Error level, and
  its `error` field names the tenant directory. Fix or revert that file in
  mctl-gitops. The refusal clears once mctl-api's checkout picks up the fix;
  nothing needs restarting. CI OIDC deploys skip this gate and are not
  affected. A stale checkout produces the same log line with a freshness
  error instead of a directory name.
