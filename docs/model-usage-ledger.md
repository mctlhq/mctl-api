# Model usage and cost ledger

Implements `mctlhq/mctl-api#266`. The record contract is ADR-012 in
`mctlhq/mctl-agents` (`docs/adr/012-model-usage-cost-attribution-contract.md`);
this document covers only what is specific to running the ledger.

The ledger is a financial read model, not a replacement for traces or for
provider invoices. It exists so that "what did this DevLoop cost" stays
answerable after trace data has aged out.

## Configuration

| Variable | Meaning |
|---|---|
| `USAGE_DB_URL` | Postgres for the ledger. Falls back to `AUDIT_DB_URL`. |
| `USAGE_PRICING_CATALOG` | Path to a JSON rate-card file. Optional. |

With no database the endpoints answer `503`. That is deliberate and must not
be softened into an empty `200`: an operator reading zero spend from an
unconfigured ledger would conclude the opposite of the truth.

With no catalog the ledger still records every token count and stores whatever
cost a producer supplies — it simply derives none of its own. That is the
honest behaviour when the rates are unknown.

## Rate cards

Rates live in a file rather than in the binary. A published price is a fact
about the world with an effective date; baking one in means a price change
needs a release, and a wrong constant silently produces plausible-looking
money.

```json
[
  {
    "version": "2026-09-01",
    "canonical_model": "claude-opus-5",
    "provider": "firstParty",
    "effective_from": "2026-09-01T00:00:00Z",
    "input_per_mtok": 0,
    "output_per_mtok": 0,
    "cache_read_per_mtok": 0,
    "cache_write_per_mtok": 0,
    "web_search_per_call": 0
  }
]
```

Rates are US dollars per million tokens, the unit providers publish, so a card
can be reviewed against the provider's own page without arithmetic.

Cost is derived once, at ingest, and the number and the `version` that produced
it are stored on the row. Adding a later card therefore cannot reach back and
change history (ADR-012 invariant 7). Correcting a *past* card is a backfill,
not a catalog edit, and is out of scope here.

## Endpoints

All three are admin-only. Aggregate spend per repository and per agent is
commercially sensitive in a way a workflow status is not.

### `POST /api/v1/usage/records`

```json
{ "records": [ { "session_id": "...", "model_key": "...", "input_tokens": 123 } ] }
```

Idempotent. The response reports `accepted` and `deduped` counts; re-delivery
is a success, not an error:

```json
{ "accepted": 0, "deduped": 1, "ids": ["<sha256>"] }
```

A producer that crashes mid-batch simply re-sends. Every record's id is
derived from its content, so the retry collides on the primary key and counts
nothing twice. Batches are capped at 500 records and 1 MiB.

### `GET /api/v1/usage/records`

Filters: `workflow_id`, `work_item_id`, `repository`, `issue`, `pr`, `agent`,
`stage`, `provider`, `model`, `outcome`, `since`, `until` (RFC3339), `limit`.

An unparseable filter is a `400`, never a dropped predicate — a caller asking
for one issue's spend must not silently receive the repository's.

### `GET /api/v1/usage/summary?group_by=agent`

`group_by` is one of `agent`, `devloop_stage`, `canonical_model`, `provider`,
`target_repo`, `temporal_workflow_id`, `work_item_id`, `outcome`. The set is
closed, so a query parameter can never become SQL.

Costs come back as three separate fields — `provider_reported_cost`,
`calculated_cost`, `invoice_reconciled_cost` — and are never summed into one
number. An estimate must not be readable as invoice truth.

## Two rules that are easy to undo

**Absent is not zero.** Every token column is nullable. A provider that does
not report cache tokens and a run that read no cache are different facts, and
`SUM()` ignores the first while counting the second. Making these columns
`NOT NULL DEFAULT 0` would silently convert "not measured" into "nothing
spent".

**The record cannot hold model content.** There is no prompt, completion or
message field on the type. That is enforced by construction rather than by a
redaction pass, so a producer written by someone who never read the ADR still
cannot leak conversation text into the ledger.

## Reconciliation

`invoice_reconciled_cost` is defined and unused. It is the hook for a future
provider billing export; reconciliation itself is out of scope for #266.
