# Commerce ledger

Implements `mctlhq/mctl-api#547` (C2 of Agent Commerce, `mctlhq/.github#173`).
The contract is ADR 020 in `mctlhq/mctl-agents`
(`docs/adr/020-capability-commerce-contract.md`); this document covers only
what is specific to running the ledger in mctl-api.

The ledger holds customer spend: commerce terms, quotes, invocation receipts
and their transition history. It is a sibling of the model-usage ledger
(`docs/model-usage-ledger.md`), which holds platform expense. The two are
never summed (ADR 020 sec. 1).

Budget reservations, the simulated `PaymentAuthorizer` and budget reads are
C3 (`mctl-api#548`), not here. Nothing in this ledger moves money: it records
the phases money state moves through, and refuses a transition that does not
match the row's current phase.

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
`refused` row holds no charge, a `released` row cannot keep `captured`, and
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
| `POST /api/v1/commerce/tenants/{tenant}/invocations/{id}/transitions` | platform admin (C3, the reconciler, the gateway); a tenant never moves its own charge |

Reason codes on refusals are those of ADR 020 sec. 13 (`identity-unresolved`,
`commerce-terms-unknown`, `quote-expired`, `quote-stale`, `quote-mismatch`,
`idempotency-conflict`, `funds-mode-unavailable`), plus `phase-conflict`,
`terms-retired` and `invalid-request` for this API's own shapes. A `phase` filter outside the
vocabulary is `invalid-request` too, never an empty listing. A missing
terms version is a plain 404; only an unresolvable capability is
`commerce-terms-unknown`. `funds_mode: live` is refused
everywhere (ADR 020 sec. 2).

## Tests

`internal/commerce` and the handler tests run against `TEST_DATABASE_URL`
and skip without it. They clean only their own rows, keyed by a
`mctl://test-commerce…` capability prefix. The concurrency test accepts the
same idempotency key from twelve goroutines and asserts one row; the lock,
the digest recomputation and the terminal check were each removed once to
confirm their tests fail.
