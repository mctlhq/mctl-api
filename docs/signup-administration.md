# Invitation administration

Use the OAuth-authenticated API MCP endpoint as a direct human platform
administrator. Service, agent, delegated and relayed callers cannot decide
invitations or set capacity. The shared MCP portal hides these private tools.

1. `mctl_list_signup_requests`: inspect saved contact data and current decision.
   Follow the returned cursor until `traversal_complete=true`.
   `complete=false` or `observation=partial` surfaces unreadable individual
   records alongside usable requests. A malformed/unreadable page is an error,
   never an empty queue. Requests past retention are explicitly listed as expired. Contact data was supplied by the applicant.
2. `mctl_signup_capacity` without arguments: inspect funded slots, reservations
   and availability. The initial budget is zero. A positive budget requires an
   independently reviewed resource assessment for production plus preview,
   CPU, pods, storage bytes and operational headroom. Setting slots requires
   a reason and `confirm=yes`; it does not resize or inspect Kubernetes.
3. `mctl_decide_signup_request(request_id, decision, reason, confirm=yes)`:
   decision is `approved` or `rejected`. The reason is sent to the applicant's
   original email address. Approval resolves the public GitHub login to its
   numeric ID, refuses pilot-cohort duplicates and atomically reserves one
   slot. The optional `github` argument explicitly selects or corrects the unverified
   supplied login; both the original submission and verified selection are kept.
   Capacity exhaustion returns `signup_capacity_exhausted` and leaves the
   request pending, with no access or decision email. Rejection needs no slot.
4. Inspect the request again: `notification_pending` means the durable email
   outbox has not acknowledged delivery. Provider acceptance does not prove
   mailbox delivery. Never ask the applicant to resubmit to retry notification.

Deployments without the customer identity hook, or with the principal store
explicitly disabled/absent by configuration, keep their static policy and legacy
provisioning path. Once the approval store is configured, a failed store init or
query refuses admission; it never disables the gate. In the private rollout,
only the explicit pilot cohort or an approved, unexpired invitation may create
a customer workspace. Having a principal from an earlier API sign-in is not an
invitation. Existing allocated workspace access is unchanged. The one-workspace
rule for non-admins predates this change and remains in force; full verified
deletion releases the reservation. At zero funded capacity, approving a new
non-pilot allocation is deliberately refused even when the human account already
exists. In public `*` mode, new customers atomically claim the same budget without
an invitation; public mode never exempts them from capacity. Public switches stay
closed in this delivery. The explicit pilot/admin exemptions remain unchanged.

Unused approval lasts seven days. GitHub ownership is proven during OAuth,
not by the supplied name/email. The site admission mirror helps render the UI;
PostgreSQL and the identity hook remain authoritative. Customer provisioning
claims a reservation before side effects and pins it to one principal and team
name. Retry the same team name after an ambiguous failure. Do not free a claim
by timeout: a workflow may already exist. Full verified customer deletion
releases the claim and invitation authority in the final database transaction.

The current funded upper profile uses production requests up to 1 CPU/2 GiB,
limits 2 CPU/3 GiB, up to 10 pods, 5 PVCs and 10 services, plus the existing
preview profile (1 CPU/2 GiB requests). The MCP create operation's historical
limits default to 3 CPU/4 GiB; an invited external customer must explicitly use
`quota_cpu_lim=2` and `quota_memory_lim=3Gi`. Its smaller default production
requests (500m/1280Mi) fit inside the funded ceiling. Other custom profiles are
refused rather than spending the same slot on a larger workspace. Future quota
changes require updating this contract and recalculating the funded budget.

Decisions retain actor, time and reason. The Worker stores immutable submissions
for 90 days; the API redacts contact/project payload and reason after 90 days,
while retaining admission/claim identifiers needed for enforcement and audit.
Email retries lease work across replicas and use one stable Resend key per
decision. Automatic retries stop 23 hours after their first attempt, before the
provider's 24-hour idempotency window; uncertain older pending deliveries need
operator reconciliation. No automatic retry may mint a fresh key. Reconciliation
of a stranded pre-provision claim or an uncertain old delivery remains an
explicit operator task requiring verified absence and currently manual database
maintenance (no automatic release API); do not infer absence from an unavailable provider.

The canonical rollout/capacity assessment is in
[mctl-web's onboarding plan](https://github.com/mctlhq/mctl-web/blob/main/docs/plans/site-onboarding-review.md).
