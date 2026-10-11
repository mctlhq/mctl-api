# Commerce ledger

Implements `mctlhq/mctl-api#547` (C2 of Agent Commerce, `mctlhq/.github#173`)
and `mctlhq/mctl-api#548` (C3: tenant budgets, holds and the simulated
`PaymentAuthorizer`).
The contract is ADR 020 in `mctlhq/mctl-agents`
(`docs/adr/020-capability-commerce-contract.md`); this document covers only
what is specific to running the ledger in mctl-api.

The ledger holds customer spend: commerce terms, quotes, invocation receipts
and their transition history. It is a sibling of the model-usage ledger
(`docs/model-usage-ledger.md`), which holds platform expense. The two are
never summed (ADR 020 sec. 1).

Nothing in this ledger moves money. A budget is a limit, never a balance
(see "Budgets" below): nothing is deposited, nothing is redeemable, and the
only `PaymentAuthorizer` is the simulated one, which records its own
authorizations, captures and voids in the same database.

## Configuration

| Variable | Meaning |
|---|---|
| `COMMERCE_DB_URL` | Postgres for the ledger. Falls back to `AUDIT_DB_URL`. |
| `COMMERCE_DISABLED` | Kill switch, same values as the other kill switches. Routes answer 503. |

Without a database every `/api/v1/commerce*` route answers 503: "the ledger
is off" and "this tenant was not charged" must never be the same answer.

Deploying this ledger enables no payment behaviour. No terms exist until a
platform admin publishes them, and nothing mints a quote until C4
(`mctl-agents#619`) wires the gateway. ADR 020 sec. 14: merging enables
nothing.

## Tables

All four are created on start by `internal/commerce.NewStore`, beside the
existing tables, never inside them. None stores arguments, results, payment
proofs or `external_ref` contents.

| Table | Holds |
|---|---|
| `commerce_terms` | one row per `(terms_id, terms_version)`; immutable once written, `retired_at` is the only column that changes |
| `commerce_quotes` | one row per quote, with its stored `quote_digest` |
| `commerce_invocations` | one row per accepted invocation; `UNIQUE (tenant_id, principal_id, idempotency_key)` is the idempotency scope of ADR 020 sec. 6, `UNIQUE (quote_id)` binds a quote to one invocation |
| `commerce_invocation_transitions` | append-only history, one row per phase change |

## Identity binding

`tenant_id` comes from the path (normalized), `principal_id` from the
canonical principal (`prn_…`) the auth middleware resolved,
`subject_principal_id` is that same principal, and `payer_account_id` is
derived server-side (`acct_tenant_<tenant>` in the simulated milestone). A
body that names any of them, or a `delegation_grant_id`, is refused as an
unknown field. Delegated subjects are not accepted yet: when the gateway
starts minting on behalf of a subject (C3/C4), the subject and grant come
from `internal/delegation.Resolver`, never from a caller. A caller with no resolved
principal is refused with `identity-unresolved` before any row exists: a
quote with no canonical principal cannot be idempotent, approved or charged.

Tenant-scoped routes require tenant authority at the milestone role (tenant
owner; `mctl-api#489` decides the final roles) or a platform admin. Another
tenant's resource answers the same 404 as a missing one.

## Digests

Two digests are computed in Go and pinned to the golden vectors of ADR 020
secs. 5 and 8 in `internal/commerce/digest_test.go`; C4's Python test pins
the same values, so the two implementations cannot drift silently.

- `quote_digest`: sha256 over the `mctl-commerce-quote/v1` length-prefixed
  encoding (`<field>:<byte length>:<value>\n` per field after a version line,
  the encoding action approvals already use). `expires_at` is encoded as
  `YYYY-MM-DDTHH:MM:SSZ`, second precision, literal `Z`.
- `terms_binding`: sha256 over `mctl-commerce-terms/v1`, the price an approval
  binds. It carries no quote id and no expiry, so an approval decided hours
  earlier still matches the quote minted after it.

`AcceptInvocation` recomputes the stored quote digest, so a quote row edited
behind the API is refused with `quote-mismatch`.

## Phase machine

```text
accepted ──► reserved ──► dispatching ──► dispatched ──► finalized
    │            │              │               │
    └► refused   └► released    ├► released     └► outcome_unknown ──► finalized
                                └► outcome_unknown
```

`Transition` locks the row, compares its phase with `expected_phase`, and
rejects a mismatch (`phase-conflict`) or a terminal row. Each of the four
facts is validated against its vocabulary on every edge, and the columns
carry matching `CHECK` constraints, so a typo from a programmatic caller is
refused rather than stored. The constraints are added by name on every start
(guarded `ALTER TABLE ... ADD CONSTRAINT`), so a table created by an earlier
build gets them too. Combinations the phase implies are closed as well, on
the values about to be stored (an omitted fact inherits the row's value and
must satisfy the same rule): a
`refused` row holds no charge and no `captured` payment, a `released` row
cannot keep a `captured` charge or payment, `outcome_unknown` cannot carry a known outcome, and
a `finalized` row cannot pair `captured` with a `denied`/`voided` payment or
`released` with a `captured` one. `finalized_at` is set only on `finalized`;
refused and released rows carry their moment in `updated_at`. `finalized` requires
`execution_outcome` of `succeeded` or `failed`, a `charge_status` of
`captured` or `released`, and a `usage_quantity`. `reserved` requires a
`reservation_deadline`. `refused` and `released` require a `reason_code`.

`payment_status: none` is the state of a paid invocation before C3 authorizes
it. It mirrors `charge_status: none` and is a C2 addition to the vocabulary of
ADR 020 sec. 11; `not_required` stays reserved for free terms.

Every non-terminal row carries a `reconciliation_deadline` (24 h).
`GET /api/v1/commerce/invocations/overdue` lists rows past it for the operator
alert of C5. Crossing the deadline changes nothing: unknown liability never
becomes spendable because time passed.

## Routes

| Route | Who |
|---|---|
| `POST /api/v1/commerce/terms`, `POST …/terms/{id}/versions/{v}/retire` | platform admin |
| `GET /api/v1/commerce/terms`, `GET …/terms/{id}/versions/{v}` | any authenticated caller |
| `GET /api/v1/commerce/invocations/overdue` | platform admin |
| `POST /api/v1/commerce/tenants/{tenant}/quotes`, `GET …/quotes/{id}` | tenant owner or admin, resolved principal |
| `POST /api/v1/commerce/tenants/{tenant}/invocations`, `GET …/invocations`, `GET …/invocations/{id}`, `GET …/invocations/{id}/transitions` | tenant owner or admin, resolved principal |
| `POST /api/v1/commerce/tenants/{tenant}/invocations/{id}/transitions` | platform admin (the gateway, C4); a tenant never moves its own charge. Refuses `to_phase` of `reserved`, `released` or `finalized` with 400 naming the owning endpoint below |
| `PUT /api/v1/commerce/tenants/{tenant}/budget` | platform admin, audited at high risk; a limit is granted, never self-granted |
| `GET /api/v1/commerce/tenants/{tenant}/budget`, `GET …/budget/changes`, `POST …/budget/precheck` | tenant owner or admin, resolved principal |
| `POST …/invocations/{id}/reserve`, `POST …/invocations/{id}/finalize`, `POST …/invocations/{id}/release` | platform admin (the gateway, C4) |
| `POST /api/v1/commerce/reconcile/expired` | platform admin (the reconciler), audited |

Reason codes on refusals are those of ADR 020 sec. 13 (`identity-unresolved`,
`commerce-terms-unknown`, `quote-expired`, `quote-stale`, `quote-mismatch`,
`idempotency-conflict`, `funds-mode-unavailable`, `budget-exhausted`,
`currency-mismatch`, `payment-denied`), plus `phase-conflict`, `terms-retired`,
`payment-unknown` and `invalid-request` for this API's own shapes. Every
denial `…/reserve` commits is 422 with the row's reason, `quote-expired`
included: unlike the 409 of accept, there is no new quote to retry with.
`reservation-expired` is a reason code the reconciler stamps on a released
invocation, never an error code. A `phase` filter outside the
vocabulary is `invalid-request` too, never an empty listing. A missing
terms version is a plain 404; only an unresolvable capability is
`commerce-terms-unknown`. `funds_mode: live` is refused
everywhere (ADR 020 sec. 2).

## Budgets

A budget (`commerce_budgets`, one per tenant and payer account) is a monthly
limit in one currency plus a per-request maximum. It is a limit, never a
balance: there is no deposit, no top-up endpoint, nothing is redeemable, and
`funds_mode` is `simulated` by a CHECK constraint. Setting it is a platform
operation audited at high risk, and every change appends a
`commerce_budget_changes` row naming the actor and the reason (ADR 020
sec. 12: no self-granted limits). The currency cannot change while the tenant
has any reservation.

The balance read (`GET …/budget`) is computed, never stored, for the current
UTC month:

| Field | Sum of |
|---|---|
| `committed_minor` | holds captured in this period |
| `reserved_minor` | open holds whose invocation is in a known state, any period |
| `pending_liability_minor` | open holds whose invocation is `outcome_unknown`, any period |
| `available_minor` | limit minus the three above, floored at zero |

A hold is attributed to the period it was taken in, and so is its capture:
a call reserved on the 31st and captured on the 1st charges the earlier
month. A hold never resets into spendable because a month ended; only a
capture, a void or a release ends it.

### Money edges

`accepted → reserved`, `→ released` and `→ finalized` are the three edges
that move a hold, and only `…/reserve`, `…/release` and `…/finalize` may
take them; the generic `…/transitions` route refuses them with 400. Each
runs in one transaction under an advisory lock on the tenant budget and
`FOR UPDATE` on the budget and invocation rows:

- **reserve** (ADR 020 sec. 7 step 8) compares committed plus held against
  the limit and the per-request maximum, inserts the hold, asks the adapter
  for an authorization and moves the row to `reserved`. The same pure
  decision serves the non-binding `…/budget/precheck` of step 4, which
  holds nothing. Any denial refuses the invocation for good with its reason
  (`budget-exhausted`, `currency-mismatch`, `quote-expired`,
  `payment-denied`) and holds nothing; the refusal is committed and then
  reported as 422. A repeat on a reserved row returns the existing hold
  with `replayed: true`. Twelve concurrent reserves of EUR 0.12 under a
  EUR 1.00 limit end with exactly eight holds (ADR 020 invariant 11).
- **finalize** captures or releases exactly once from `dispatched` or
  `outcome_unknown`: `per_call` captures on any outcome,
  `per_successful_call` captures on `succeeded` and voids on `failed`,
  `free` finalizes a zero hold.
- **release** voids and releases from `reserved` or `dispatching`. A
  `dispatched` row is too late to cancel: its outcome must be observed, and
  the call is 409 `phase-conflict`.

### Unknown is never denied

An adapter answer the ledger cannot classify, or no answer at all, leaves
the hold in place with `payment_status: unknown` and is reported as 409
`payment-unknown`; nothing is refused and nothing is spendable again. Such
a row cannot be dispatched: `reserved → dispatching` is refused with
`payment-unknown` until a retry of `…/reserve` resolves it, by asking the
adapter for the status of the same authorization key (never a fresh
authorization): authorized is recorded and the hold replays, denied
releases the hold with nothing to void, anything else is unknown again.
Before a capture or a void, the ledger does the same lookup and proceeds
only on a definite answer; a hold whose authorization turned out denied
after dispatch is released and the row finalized with `payment_status:
denied`, so no hold is ever stuck behind an adapter's late denial.

`POST /api/v1/commerce/reconcile/expired` is the reconciler for the two
states time alone may move (ADR 020 sec. 11): an `accepted` row past its
quote expiry is refused `quote-expired`; a `reserved` row past its
reservation deadline is voided and released with `reservation-expired`, or
listed as `unresolved` and kept when its payment state cannot be confirmed.
`dispatching`, `dispatched` and `outcome_unknown` rows are never touched by
time.

### Adapter contract

`PaymentAuthorizer` (ADR 020 sec. 10) is `Authorize`, `Capture`, `Void` and
`Status`, keyed by `mctl-pay/v1:<invocation_id>:<operation>`; the same key
with different parameters is `idempotency-conflict`. An adapter declares its
features, and one missing `auth_capture`, `void` or `status_lookup` is
refused at install. The only adapter is `SimulatedAuthorizer`, which writes
`commerce_payment_operations` rows and denies `funds_mode: live` with
`funds-mode-unavailable`; a capture above the authorized amount fails.
Simulated captures are recorded `settled`.

## Tests

`internal/commerce` and the handler tests run against `TEST_DATABASE_URL`
and skip without it. They clean only their own rows, keyed by a
`mctl://test-commerce…` capability prefix. The concurrency test accepts the
same idempotency key from twelve goroutines and asserts one row; the lock,
the digest recomputation and the terminal check were each removed once to
confirm their tests fail. The budget tests were verified the same way: the
available check, the held-only-this-period sum, the budget lock, the
unknown-is-denied shortcut, the money-edge guard on `…/transitions`, the
per-request maximum and a reconciler that also touches `dispatching` rows
were each put back once and each made its test fail.
