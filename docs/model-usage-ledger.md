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

A record that matches no card is stored without a calculated cost and logs a
warning naming the model and provider. It is not an error — the token counts
are still true and a cost can be derived later — but it must not be silent: a
catalog that failed to load, or one whose cards all name a provider the
producer omits, would otherwise make every row costless with nothing pointing
at why.

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

Cards resolve on `(canonical_model, provider)`. The same model is billed
differently on firstParty, Bedrock and Vertex, so a card naming a provider
applies only to that provider; a card with no `provider` is a wildcard used
when the provider has no card of its own. Two cards for the same model,
provider and `effective_from` are rejected at load: there is no correct answer,
and picking one by sort order would price identical records differently between
restarts.

Cost is derived once, at ingest, and the number and the `version` that produced
it are stored on the row. Adding a later card therefore cannot reach back and
change history (ADR-012 invariant 7). Correcting a *past* card is a backfill,
not a catalog edit, and is out of scope here.

## Endpoints

Reads are admin-only. Aggregate spend per repository and per agent is
commercially sensitive in a way a workflow status is not.

Writing needs the `usage:write` permission. Human admins hold it. So does the
**usage writer** (`service:mctl-agents-usage`, mctlhq/.github#50), a separate
least-privilege principal for the producers: it authenticates with its own
bearer token (`MCTL_USAGE_WRITER_TOKEN`), is not an admin, belongs to no
tenant, and is refused with `403 usage_writer_route_not_allowed` on every route
except `POST /api/v1/usage/records`, including `/mcp` and the ledger's own
reads. The admin `mctl-agent` service token is deliberately not used for usage
ingestion.

The token is disabled (and logged at `ERROR`) when it is shorter than 32
characters, or equal to `MCTL_AGENT_SERVICE_TOKEN` or to any surface token:
one secret must never resolve to two principals. Unset, the principal does not
exist and only admins can write.

Every row records who wrote it: `ingested_by` (the user id) and
`ingested_by_principal_id` (the durable `prn_` principal, empty when the
principal store is not configured). Both are set by the server; a producer
cannot supply them. A re-delivered record is deduped and keeps the attribution
of its first write.

### `POST /api/v1/usage/records`

```json
{ "records": [ { "session_id": "...", "model_key": "...", "input_tokens": 123 } ] }
```

Idempotent. Re-delivery is a success, not an error. The response names which
ids landed and which collided, not just how many:

```json
{ "accepted": [], "deduped": ["<sha256>"], "accepted_count": 0, "deduped_count": 1 }
```

A producer that crashes mid-batch simply re-sends. Every record's id is
derived from its content, so the retry collides on the primary key and counts
nothing twice.

`id` is always derived server-side and never taken from the request. A
producer that could choose its own id would opt out of the guarantee entirely —
a fresh uuid per delivery makes every retry a new row. Sending an `id` that
disagrees with the derived key is a `400` rather than a silent overwrite, so a
producer computing it wrongly finds out.

Batches are capped at 500 records (`413`) and 1 MiB (`413`). The write is
all-or-nothing, and a rejection names the offending record's index.

#### Correlation fields

Every correlation field is optional, so a producer that sends none of them is
still accepted. When a field is sent, its shape is checked, because these are
the values callers filter on. A malformed value would make its record
unreachable by the query meant to find it (mctlhq/mctl-agents#499).

| Field | Shape |
|---|---|
| `target_repo` | `owner/name` |
| `issue_number`, `pr_number` | positive integer; requires `target_repo`, because a number alone does not say which repository it belongs to |
| `execution_id` | up to 128 characters from `[A-Za-z0-9_.:-]`, starting alphanumeric |
| `temporal_run_id` | up to 128 characters from `[A-Za-z0-9_.:-]`, starting alphanumeric |
| `argo_workflow_name`, `temporal_workflow_id`, `work_item_id`, `devloop_stage` | free text, unchanged |

`execution_id` identifies the runner invocation that spent the tokens. It is
the work-context store's `we_…` when the run has one, and otherwise the
runner's own execution identity (`ex-…`). The server checks only the
character set, not the prefix: the batch is all-or-nothing, and a new identity
scheme must not cost usage records. `execution_id` is not part of the dedupe
key, so sending the same result again with a different `execution_id` is
still deduped.

`temporal_run_id` names the single Temporal execution of `temporal_workflow_id`
that spent the tokens (mctlhq/.github#50 decision 4): a workflow id survives a
continue-as-new, a reset and a retry, but the run id does not, so spend is
attributable to the one execution that actually incurred it. It is optional —
a producer that does not send it is unaffected — and like every other
correlation field it is not part of the dedupe key, so sending the same
result again with a different `temporal_run_id` is still deduped.

### `GET /api/v1/usage/records`

Filters: `workflow_id`, `run_id`, `work_item_id`, `execution_id`, `repository`, `issue`,
`pr`, `agent`, `stage`, `provider`, `model`, `outcome`, `since`, `until`
(RFC3339), `limit`.

`issue` and `pr` are accepted only together with `repository`. Issue and PR
numbers repeat in every repository, so a bare `pr=12` would add up spend from
unrelated repositories. It is a `400`.

An unparseable filter is a `400`, never a dropped predicate — a caller asking
for one issue's spend must not silently receive the repository's. `limit` above
1000 is likewise a `400` rather than a quietly smaller page: on a financial read
model, a caller summing a clipped page understates real spend.

`model` matches `canonical_model`, falling back to `model_key` for records whose
producer reported only the latter. `group_by=canonical_model` uses the same
fallback, so those records are counted under their model rather than under an
empty bucket.

The response carries `truncated` and `limit`. `count` is the size of *this
page*, not the number of matching records — a caller summing
`records[].calculated_cost` must check `truncated` before treating the total as
complete.

### `GET /api/v1/usage/summary?group_by=agent`

`group_by` is one of `agent`, `devloop_stage`, `canonical_model`, `provider`,
`target_repo`, `temporal_workflow_id`, `work_item_id`, `execution_id`, `outcome`. The set is
closed, so a query parameter can never become SQL.

Results are capped the same way `records` are and the response carries
`truncated`, `truncated_by` and `limit`. Buckets are ordered by record
**count**, so truncation drops the tail by volume, not by spend: a handful of
expensive invocations can be clipped out by many cheap ones, and
`truncated_by: "record_count"` says so. A clipped bucket list is otherwise indistinguishable
from a complete breakdown, which matters most on the high-cardinality
dimensions (`temporal_workflow_id`, `work_item_id`, `execution_id`) that grow as the ledger
ages.

Costs come back as three separate fields — `provider_reported_cost`,
`calculated_cost`, `invoice_reconciled_cost` — and are never summed into one
number. An estimate must not be readable as invoice truth.

## Two rules that are easy to undo

**Absent is not zero.** Every token column is nullable. A provider that does
not report cache tokens and a run that read no cache are different facts, and
`SUM()` ignores the first while counting the second. Making these columns
`NOT NULL DEFAULT 0` would silently convert "not measured" into "nothing
spent".

**Money is `NUMERIC`, not `DOUBLE PRECISION`.** `SUM(double precision)` is
order-dependent in Postgres and a parallel aggregate plan does not fix the
partial-sum order, so the same summary could return slightly different totals on
successive calls.

**The record cannot hold model content.** There is no prompt, completion or
message field on the type. That is enforced by construction rather than by a
redaction pass, so a producer written by someone who never read the ADR still
cannot leak conversation text into the ledger.

## Reconciliation

`invoice_reconciled_cost` is defined and unused. It is the hook for a future
provider billing export; reconciliation itself is out of scope for #266.
