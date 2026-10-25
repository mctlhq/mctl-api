# SecurityFinding v1: durable store and REST API (mctl-api#774)

This is the normative v1 contract of the SecurityFinding lifecycle, slice 1
of mctlhq/.github#209. It is implemented by `internal/securityfindings` and
`internal/api/handlers_security_findings.go`; the wire shapes are in
`internal/openapi/openapi.yaml` under the `SecurityFindings` tag.

The spike's flat D4 model (one finding row with `vulnerable_rev` / `fixed_rev`
and a single WorkItem) is **not** normative. The dependent slices
(mctlhq/mctl-agents#778, the remediation and verification runner, and
mctlhq/mctl-gitops#2103, provider ingestion and configuration) build against
this document only.

## Model

Three levels plus append-only evidence:

```
SecurityFinding (sf_)         canonical problem identity and grouping
  SecurityOccurrence (soc_)   one concrete affected subject; owns the lifecycle
    ProviderObservation (sob_)   append-only evidence, immutable
    RemediationAttempt (sra_)    one fix cycle; history is never overwritten
      VerificationRecord (svr_)  immutable
    occurrence event log         append-only, immutable, one row per change
```

Lifecycle state is stored **only** on the occurrence. No mutable
`vulnerable_rev` / `fixed_rev` pair is authoritative: revisions live on
observations, attempts (`affected_revisions`, `landed_*`) and verifications.
`current_affected_revision`, `current_affected_artifact` and
`active_attempt_id` on the occurrence are read projections.

References, hashes, revisions and artifact digests are stored, never scanner
or code payloads. `work_item_id` is a correlation, not a foreign key
(docs/work-context-contract.md), so history survives a WorkItem retention
purge.

## Canonical identity and occurrence identity

**Problem identity** is normalized and scoped to the tenant:

| Input | Canonical key |
| --- | --- |
| `CVE-YYYY-N` (any case) | `cve:CVE-YYYY-N` |
| `GHSA-xxxx-xxxx-xxxx` (any case) | `ghsa:ghsa-xxxx-xxxx-xxxx` |
| anything else | `rule:<provider_ref>:<rule_id>` (provider-scoped; rule ids are not portable) |

When an item carries several identities (`identity` plus `aliases`), the CVE
is canonical, then the GHSA, then the primary rule id; the others are aliases.
A finding is found by **any** recorded alias. If an item's aliases resolve to
two different existing findings the item is rejected with
`finding_alias_conflict` and nothing is merged (a merge operation is
deferred).

**Subject** is `{repository, resource, package_purl, path, location,
artifact_digest, service, rule_id}`, normalized (lowercased host/owner/repo,
cleaned paths, sorted purl qualifiers). `subject_fingerprint` is the SHA-256 of
its canonical sorted-key JSON. The **revision is not part of it** (it changes
across fixes); the **artifact digest is**, so a source state and a deployed
artifact state are distinct occurrences. For `rule:` identities the rule id is
part of the subject.

An occurrence is unique per `(finding, subject_fingerprint)`:

- Same CVE in two repositories, two artifact digests, two package locations
  or two code locations: **distinct occurrences**, independent lifecycle.
- Two providers, same canonical identity and same fingerprint: **one
  occurrence**, two observations.
- A subject with only a CVE/CWE/rule id and a repository, with no package,
  path, location or artifact identity: rejected with `subject_too_weak`. The
  minimum is a repository or resource **and** at least one of `package_purl`,
  `path`, `location`, `artifact_digest`.

## Provider trust and ingestion

`POST /api/v1/security/observations` is the only route a security-provider
principal may call (`securityProviderGate`). The principal is minted from its
own token:

- `SECURITY_PROVIDERS`: non-secret JSON, `[{"ref","max_strength","tenants"}]`.
- `MCTL_SECURITY_PROVIDER_TOKENS`: Secret, one `ref=token` line per provider.
  A token must be at least 32 characters and unique across every other
  configured principal token and across providers; a provider with no token,
  no configuration entry or a refused token is disabled with an error log.
- The principal is `service:security-provider:<ref>`. It is not an admin,
  belongs to no tenant and holds exactly `security:ingest`.

`provider_ref`, the provider's maximum verification strength and its tenant
allowlist come **solely** from the authenticated principal and that server-side
configuration. A `provider` (or `provider_ref`, `source`) field in the payload
is stored only as `untrusted.claimed_provider`; it is never used for identity,
dedup scope, authority or strength. An admin may ingest directly (bootstrap,
testing) under `provider_ref = "admin:<user id>"` with the ceiling
`provider_claim`.

A batch holds 1 to 100 observations (body cap 1 MiB). Each item runs in its own
transaction under an advisory lock on its finding identity and gets its own
result in `results[i]`: `created`, `duplicate`, or `rejected` with a code
(`subject_too_weak`, `finding_alias_conflict`, `invalid_request`,
`tenant_not_allowed`, `internal_error`). A rejected or duplicate item never
drops a later one.

**Dedup key.** `observation_hash = sha256(canonical JSON of {identity_key,
subject_fingerprint, source_finding_id, claimed_action, observed_revision,
observed_artifact_digest, delivery_id, evidence_digest})`, unique per
`provider_ref`. Redelivery of the same content is a `duplicate` that returns
the original observation id and writes no row or event. `(provider_ref,
delivery_id)` is **never** a key by itself: several findings in one delivery
have distinct hashes. The same state seen again in a new delivery is new
evidence.

**Untrusted data.** Title (256 B), severity (32 B) and description (4096 B) are
stored only in the bounded `untrusted` object. No transition, policy or
authorization code reads it, and no transition input type has a field for it.

### Effect of an observation

| `claimed_action` | Occurrence | Effect |
| --- | --- | --- |
| `present` | new | created in `open` |
| `present` | `resolved` | `reopened` when observed after the resolution and not at a revision or artifact already recorded as affected before the resolving fix; otherwise recorded only |
| `present` | any other | recorded; projections updated |
| `fixed` | any | recorded as `provider_claim` evidence; when `awaiting_verification` and bound to the landed revision, a verification at strength `provider_claim`, which cannot meet the default minimum |
| `absent` | `awaiting_verification` | when bound to the landed revision or artifact, a `passed` verification at `min(scanner_rerun_exact_revision, provider ceiling)`; unbound: recorded only |
| `withdrawn` | any | recorded only; a human may dismiss with `provider_withdrawn` |

A `dismissed` occurrence keeps recording observations without changing state.

## Lifecycle

States: `open`, `triaged`, `fixing`, `awaiting_verification`, `resolved`,
`reopened`, `unverifiable`, `dismissed`. The transition table
(`securityfindings.Transitions`) is the single enforcement point. Anything else
is refused with `invalid_transition` (409). There is no generic set-state
operation.

```
open|reopened         --triage-------------------> triaged
open|triaged|reopened|unverifiable
                      --start_remediation--------> fixing   (new attempt)
fixing                --record_fix (landed)------> awaiting_verification
awaiting_verification --verify_passed------------> resolved (attempt: resolved)
awaiting_verification --verify_failed------------> fixing   (attempt stays active)
awaiting_verification --verify_inconclusive------> awaiting_verification
awaiting_verification --verify_unverifiable------> unverifiable
resolved              --regress (observation)----> reopened
open|triaged|fixing|awaiting_verification|reopened|unverifiable
                      --dismiss------------------> dismissed
```

`resolved` is reachable only through a verification. `resolved` and
`dismissed` accept only the moves listed.

- **Start remediation** creates a new attempt referencing an existing WorkItem
  in the same tenant (`work_item_not_found`, 404, otherwise). At most one
  active attempt per occurrence, enforced by a partial unique index on
  `security_remediation_attempts (occurrence_id) WHERE outcome IS NULL`; a
  second start is `remediation_attempt_active` (409). Starting from
  `unverifiable` closes the previous attempt as `superseded` in the same
  transaction. Attempts have a per-occurrence `seq`.
- **Record fix** with `landed=true` needs `landed_revision` or
  `landed_artifact_digest`, and moves to `awaiting_verification`, never to
  `resolved`. `landed=false` records only a `candidate_revision`.
- **Record verification.** The verification's revision and artifact digest must
  match the attempt's landed ones (each one the attempt has set must match);
  otherwise `verification_not_bound` (422) and nothing changes. Results:
  `passed` (resolves only when the derived strength meets the minimum),
  `failed` (back to `fixing`, attempt active), `unavailable` / `error` /
  `timeout` (recorded, stays `awaiting_verification`, **never** treated as
  absence or resolution), `unverifiable` (to `unverifiable`, attempt history
  kept).
- **Regression.** A resolved occurrence reopens on a `present` observation
  observed after the resolving attempt ended and not at a revision or artifact
  recorded as affected before the fix landed. The next remediation creates a
  new attempt; every earlier attempt, fix and verification is preserved.
  Ancestry-aware regression detection is out of scope: a scanner rescanning an
  old, unlisted revision can cause a false reopen.
- **Dismiss** needs an authenticated **human**: a human platform admin, or a
  human holding at least the `owner` role on the occurrence's tenant. It needs
  an `authority_ref` and a reason in `false_positive`, `accepted_risk`,
  `duplicate`, `not_applicable`, `provider_withdrawn`, and closes any active
  attempt as `cancelled_dismissed`. A service, agent, surface, relayed,
  delegated or provider principal is refused with 403. A `resolved` occurrence
  cannot be dismissed.

Every transition appends an event with the actor, the actor's principal id, the
relaying principal id, the source (`provider:<ref>`, `api`, `agent:<name>`), a
reason and a timestamp, and bumps `state_version`. Mutating requests accept an
optional `expected_state_version` (`version_conflict`, 409).

## Verification strength

Ordered strongest to weakest: `deterministic_regression_test` >
`assurance_replay` > `scanner_rerun_exact_revision` > `provider_claim` >
`manual`.

A verification's strength is **derived**, never read from free payload text:
`derived = min(declared mechanism, ceiling of the authenticated recorder)`.
The ceiling is the provider's configured `max_strength` for a provider,
`deterministic_regression_test` for the service principal or an agent run
holding `security:remediate`, and `manual` for a human. `assurance_replay`
additionally needs an evidence ref of kind `assurance_finding`; without it the
derived strength is capped at `provider_claim`.

An occurrence resolves only when a `passed`, bound verification's derived
strength is at least `SECURITY_FINDING_MIN_VERIFICATION_STRENGTH` (default
`scanner_rerun_exact_revision`). An unknown value disables the store (the
routes answer 503) rather than silently weakening the policy. A weaker pass is
recorded and leaves the occurrence `awaiting_verification`.

## Authorization

| Operation | Allowed |
| --- | --- |
| Ingest observations | security-provider principal (this route only), admin |
| Read findings and occurrences | tenant members; admins read all. A row in another tenant answers **404**, never 403 |
| Triage, start remediation, record fix, record verification | `security:remediate` (the service principal, or an agent run minted with it), or a human with at least the `developer` role on the tenant (admins included) |
| Dismiss | human platform admin, or human with at least `owner` on the tenant |

## Persistence

Schema `securityfinding/v1`, applied idempotently at startup in the evidence or
audit database. Tables: `security_findings`, `security_finding_aliases`,
`security_occurrences`, `security_observations`,
`security_remediation_attempts`, `security_verifications`,
`security_occurrence_events`, `security_requests` (idempotency). `BEFORE UPDATE`
triggers make observations, verifications and events immutable.

Configuration: `SECURITY_FINDINGS_DB_URL`, else `EVIDENCE_DB_URL`, else
`AUDIT_DB_URL`; `SECURITY_FINDINGS_DISABLED` is a kill switch;
`SECURITY_FINDING_MIN_VERIFICATION_STRENGTH`; `SECURITY_PROVIDERS` and
`MCTL_SECURITY_PROVIDER_TOKENS` for providers (helm: `securityProviders`,
`securityProviderTokensSecret`). A store that is not configured or not
available answers `503 security_findings_store_unavailable` on every route,
never an empty list.

## Idempotency

A mutating request that repeats an `Idempotency-Key` with the same body and
actor returns the original result (`replayed: true`); the same key with a
different body or actor is `idempotency_key_reused` (409). Observation ingest
has no key: it deduplicates by content hash.

## Error codes

`security_findings_store_unavailable` (503), `not_found` (404),
`work_item_not_found` (404), `invalid_request` (400), `invalid_transition`
(409), `remediation_attempt_active` (409), `finding_alias_conflict` (item
level), `version_conflict` (409), `idempotency_key_reused` (409),
`verification_not_bound` (422), `subject_too_weak` (item level),
`forbidden` (403), `security_provider_route_not_allowed` (403).

## Rollout gate for the dependent slices

Ship disabled-by-config: with no providers configured only admins can ingest;
with no database URL every route answers 503. mctl-gitops#2103 then adds the
provider configuration and tokens; mctl-agents#778 is minted
`security:remediate`. Both wait for this release. Rolling back is a revert, or
`SECURITY_FINDINGS_DISABLED=true`, which makes every route answer 503 without
touching data; removing a token from the Secret revokes that provider's ingest
immediately.

## Open points

- **Tenant attribution.** Each observation names its tenant, which must be in
  the provider's configured allowlist. Deriving the tenant from a
  repository-to-tenant mapping is an alternative that mctl-gitops#2103 may
  provide instead.
- **Alias merging.** An observation linking two already-separate findings is
  rejected, not merged.
- **Minimum strength below `scanner_rerun_exact_revision`** is allowed by
  configuration but not the default.
- **Observation retention** is not part of this slice.
