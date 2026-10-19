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
`decision_context`. An `approve` is refused with 422
`approval_context_incomplete` (`details.missing_fields`, request stays pending)
unless all of these are present. A `deny` is never gated.

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

## Privacy rule

The context holds references, digests, enums and reason codes only. It never
holds args, the free-text `reason`, or a payload. The audit log follows the
same rule.

## Captured and revalidated facts

Captured when a human approves: `decided_context_digest`, `authority_basis`
(`platform_admin`; `unrecorded` on legacy rows), `authz_mode`, and
`fresh_until = min(expires_at, decided_at + ACTION_APPROVAL_MAX_DECISION_AGE)`.

Revalidated when the approval is spent (`POST .../consume`, and the
grant-authorized `mctl-agents-approve`), in this order, first failure wins:

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

A refusal never spends the approval and never reaches the executor. The store's
compare-and-set also enforces `fresh_until` atomically. Authority and policy are
checked milliseconds before it; the remaining race is bounded by the facts that
need a redeploy or a principal-store transaction to change.

## Refusal codes

Callers should key on `details.reapproval_required`, not on the code text.

| Code | HTTP | `reapproval_required` | Finding |
|---|---|---|---|
| `approval_context_incomplete` (decide) | 422 | no grant made | F6 |
| `approval_context_invalid` (create) | 400 | n/a | F6 |
| `approval_context_changed` | 409 | true | F6 |
| `approval_stale` | 409 | true | F4 |
| `approval_expired` | 409 | true | F4 |
| `approval_authority_revoked` | 409 | true | F3 |
| `approval_decider_disabled` | 409 | true | F3 |
| `approval_authority_unavailable` | 503 | false: retry, the approval is not spent | F3 |
| `approval_policy_drift` | 409 | true | F9 |

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
