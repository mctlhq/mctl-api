# Glovo provider contract and reorder planner (mctl-api#1006)

The provider-neutral core of the Glovo real-provider direction. Packages:

- `internal/glovoprovider`: the `Provider` read interface, the gated
  `CartWriter` write interface, the minimized read model, typed errors and the
  cart fingerprint.
- `internal/glovoprovider/synthetic`: the deterministic fixture provider, with
  invented stores, products and orders (`synthetic/testdata/`).
- `internal/glovoprovider/reorder`: the Reorder Planning Engine, which turns a
  past order into a read-only `BasketIntent`.

Nothing here performs network I/O or is wired into a route, an MCP tool or
startup. The live adapter (`internal/glovoprovider/live`, see "Live adapter"
below) is the only package that does network I/O, and nothing imports it
outside its own tests. Release holds (mctl-api#934,
mctl-gitops#2528) and the G3 provider-access gate are unaffected.

## Synthetic fixture vs live provider

The live column is the requirement on a future adapter. Which upstream calls
satisfy it is for the read-only `denya/glovo-skill` audit to settle.
"Unobserved" means `ErrUnobserved` and "absent" means `ErrAbsent`.

| `Provider` method | Synthetic fixture | Live adapter must |
| --- | --- | --- |
| `Location` | fixed `ZZ` / `SYN-CITY-1` / `EUR` | return only a country code, a city code and a currency; keep coordinates and the address in the user's own session |
| `Stores` | 3 stores (restaurant, closed restaurant, Express) | accept a limit of 1..50; a failed or partial page is unobserved, never a shorter list |
| `Catalog` | per-store menu with option groups | return the whole menu or unobserved; a store reported gone is absent |
| `Search` | name substring within one store | accept a limit of 1..50; an empty result needs a clean provider response |
| `Product` | lookup in the store catalog | return options, availability and price in integer minor units |
| `OrderHistory` | 3 orders, newest first | accept a limit of 1..`MaxHistoryOrders` (20); return summaries without address, phone, courier or customer data |
| `Order` | items with options and historical unit prices | drop every personal field at the boundary; a missing order is absent |
| `Cart` | one Express line; `Scenario.Cart` replaces it | report an empty cart as zero lines and a failed read as unobserved; compute `Fingerprint` with `CartFingerprint` |
| `CartWriter.ApplyCart` | `ErrNotSupported` | stay unwired until its own approved gate, then follow the write protocol below |

Scenario knobs (`synthetic.Scenario`, files in
`synthetic/testdata/scenarios/`): `unavailable_products`, `removed_products`,
`price_overrides`, `removed_options`, `removed_stores`, `cart` and `fail_ops`.
`fail_ops` makes the named reads fail as unobserved.

## Could not observe vs absent

- A read that failed, timed out, was cancelled, came back malformed or stopped
  after a partial page is `ErrUnobserved`. It is never an empty slice, a zero
  or "unavailable".
- Only the provider's own absence signal is `ErrAbsent`.
- An observed empty result is a non-nil empty slice with a nil error.
- `ReadError.Error()` names only the operation and the kind. The provider
  cause stays reachable through `errors.Is`, but its text is never formatted,
  so a session detail cannot reach a log line.
- In the planner, an unobserved catalog or cart fails the whole plan. A store
  reported absent is an observation, so every line of the plan becomes
  `unavailable` with `store_unavailable`.

## Reorder contract

Input: one `HistoricalOrder`, a `Snapshot` (catalog and cart),
`Constraints` (`exclude_category_tags`, `max_budget_minor`), the clock `Now`
and a TTL (15 min by default, 1 h at most). `Build` and `Revalidate` are pure.
`Gather`, `Plan` and `RevalidateFrom` only read.

Steps:

1. Merge duplicate lines (same product, same options) and sort them by key, so
   the order of input lines never matters.
2. Match each line to the current catalog. The matching is conservative:
   - Same product id and same normalized name: exact match.
   - Same id with another name: a candidate (`product_renamed`).
   - Otherwise, name similarity is the token-set Jaccard index in thousandths.
     Below `CandidateThresholdPermille` (600) the line has no match. When the
     runner-up is within `AmbiguityMarginPermille` (100) of the best, the line
     is `ambiguous` and lists every candidate. A single candidate is a
     substitution (`product_id_changed`).
   - A name match is never accepted automatically, whatever its score.
3. Verify the matched product:
   - An unavailable product makes the line `unavailable`.
   - A required option group that cannot be satisfied makes it
     `missing_required_options`.
   - A dropped optional modifier makes it a candidate: the line is not the
     same product any more.
4. Filter by category tags, taken from both the history and the current
   category. A filtered line keeps its class and gains `excluded_category`.
5. Apply the budget greedily in canonical order. A line that would exceed it
   gets `over_budget`.

Output (`Intent`, `v = mctl-reorder-intent/v1`):

- `lines`: exact matches only, at current prices, with the unit price delta
  against history.
- `substitutions`: candidates for the user to confirm. They are never added
  and never counted in the estimate.
- `excluded`: every other line, with its class and reason codes.
- The estimated and historical subtotals and the price delta.
  `historical_currency` names the currency of the historical figures; when
  it differs from `currency`, the delta is not computed and the
  `currency_mismatch_price_delta_unknown` warning is set. Fees are not
  estimated, and the `fees_not_estimated` warning says so.
- Warnings, for example `native_reorder_unavailable_manual_reconstruction`.
  `native_reorder_allowed = false` does not block a manual reconstruction.
- The cart fingerprint at plan time, `created_at`, `expires_at` and
  `digest`. The digest is `"sha256:" + hex(sha256(JCS(intent without
  digest)))`, built the same way as the basket fingerprint
  (`internal/jcs`, `basket.Fingerprint`).

Every historical line appears exactly once, in one of `lines`,
`substitutions` or `excluded`. Any change to the intent changes the digest,
and `VerifyDigest` detects tampering.

## Revalidation and approval state machine

```
plan ──> intent(digest) ──human approval binds digest──> approved
approved ──Revalidate──> unchanged        -> may proceed to the write protocol
                      ├─> material_change -> new plan, new approval
                      ├─> expired         -> new plan, new approval
                      ├─> unknown         -> no claim; retry the read, never proceed
                      └─> tampered        -> refuse
```

`Revalidate` checks the verdicts in this order: tampered, expired, unknown,
then material change. A material change is any of:

- the price of an approved line or a substitution changed (options
  included);
- an item became unavailable or was removed;
- the product id now carries another name (`renamed`), because it may be a
  different item;
- the product moved into a category the user excluded;
- the store closed after planning, unless the intent already warned
  `store_closed`;
- an option was removed or a required group became unsatisfiable;
- the store was removed;
- the currency changed;
- the cart fingerprint changed.

Changes to excluded lines are not material, because the human did not
approve them.

`Build` and `Revalidate` recompute `CartFingerprint` from the observed cart
lines. A snapshot whose stored fingerprint is empty or does not match its
content is treated as unobserved, so an adapter cannot hide a cart change
behind a stale value.

## Write protocol (`CartWriter`, not wired)

```
planned -> cart_reread -> grant_verified -> writing -> verify_reread -> reconciled
              |               |               |             |
              v               v               v             v
     precondition_failed  precondition_failed  reconcile_unknown  reconcile_mismatch
                                                    |
                                                    v
                                          verify_reread (read only)
```

1. Reread the cart and compare it with `expected_cart_fingerprint`.
2. Verify that `approval_grant_ref` is a live human approval bound to
   `intent_digest`. The approval service does this, not the adapter.
3. Write once.
4. Reread the cart.
5. Reconcile the reread against the request.

A write whose outcome is unknown, for example after a timeout, goes to
`reconcile_unknown`. From there only a read is allowed, never a retry of the
write. `CanTransition` encodes this, and a test pins it.

## Privacy minimization

- The read model has no field for an address, a street, a postcode, a phone,
  an email, a customer, a courier, a rider, coordinates, a name, a birth date,
  a card, an IBAN, a token, a session, a cookie, a password, a user or an
  account. `TestTypesCarryNoPersonalFields` walks every exported type
  reflectively. `TestFixturesCarryNoPersonalData` scans every fixture key and
  string for such keys and for email or phone shapes. The fixture decoder also
  refuses unknown fields.
- Must never reach the model, an audit record or a trace: the provider
  session, its tokens or cookies, the delivery address and coordinates, phone
  numbers, emails, the names of the customer or the courier, and payment data.
  The live adapter drops all of these when it parses a response, before
  building any type here.
- What may appear: the ids, names and prices of stores, products and options,
  the past order id, the plan's reason codes, and the digests.
- Error text carries only fixed operation and kind strings, never provider
  response text.

## Live adapter (`internal/glovoprovider/live`)

A port of a small subset of `denya/glovo-skill` (commit
`42f25483bf305f8c3c26d1212080e05849c1e563`, `api.mjs`) onto the `Provider`
interface, for the owner's own Glovo account (mctl-api#1006, owner decision
2026-11-11). Not wired into any route or MCP tool; `TestLiveAdapterIsNotWired`
fails if a non-test file outside the package imports it.

- `Reader` implements `glovoprovider.Provider` and has no write method.
- `Writer` embeds a `Reader` and adds `ApplyCart` through the separate
  `CartMutator` interface (add with options, set quantity, remove).
- The bearer comes from an injected `TokenSource` (`Token`, `Refresh`); the
  adapter never stores or logs it.
- Store ids are `"<storeId>:<storeAddressId>"`, the pair every Glovo store
  endpoint needs.

| Upstream tool | Outcome |
| --- | --- |
| `glovo_get_saved_locations` | ported as `Location`: only country and city codes are read, to prove the account has an address in the configured city; every other field is never decoded |
| `glovo_browse_stores` | ported as `Stores` (restaurant and grocery walls, limit 1..50) |
| `glovo_search_store_items` | ported as `Search` |
| `glovo_get_product` | ported as `Product` (modifier groups, price, availability) |
| `glovo_get_purchase_history` | ported as `OrderHistory` (cursor pages of 15, then each order detail) |
| `glovo_get_order_items` | ported as `Order` (404 is `ErrAbsent`) |
| `glovo_get_basket` | ported as `Cart` and `Reader.CartForStore` (basket id and `basketVersion` kept internally; the version is `CartSnapshot.Version`) |
| `glovo_add_to_basket`, `glovo_set_quantity`, `glovo_remove_from_basket` | ported as `Writer.ApplyCart`, not reachable from any tool |
| `glovo_get_store_menu`, `glovo_browse_store_catalog` | `Catalog` returns `ErrNotSupported`: the menu is a lazily fetched tree and a partial menu would break "whole menu or unobserved" |
| `glovo_get_shopping_guide`, `glovo_auth_status`, `glovo_get_location`, `glovo_get_store`, `glovo_get_store_recommendations`, `glovo_get_store_order_options`, `glovo_get_suggestions`, `glovo_preview_reorder`, `glovo_plan_reorder`, `glovo_get_order_stats`, `glovo_analyze_order_history` | not ported: not needed by the `Provider` model (planning is `internal/glovoprovider/reorder`) |
| `glovo_search_locations`, `glovo_select_location`, `glovo_set_location` | excluded: location change |
| `glovo_login` | excluded: session custody is a separate component |
| checkout, payment, order placement | not in upstream and not implemented |
| `Glovo-Perseus-Consent: essential_functional_marketing` header | not sent: the adapter never asserts marketing consent |

Safety properties, each with a test that fails when the property is removed
(mutation-verified):

- Host allowlist: only the configured API host; a redirect is never followed
  (3xx is `ErrUnavailable`) and the transport refuses any other host.
- Every request has a deadline (`RequestTimeout`, or the caller's if shorter)
  and a body size cap (`MaxResponseBytes`).
- A 401 triggers one `TokenSource.Refresh` and one replay, then `ErrAuth`.
  There is no other retry (429 is `ErrRateLimited`, not retried).
- Non-2xx, truncated, malformed or drifted bodies are `ErrUnobserved` with
  cause `ErrUnavailable`, `ErrSchemaDrift`, `ErrAuth`, `ErrRateLimited` or
  `ErrResponseTooLarge`, never an empty list. A clean `[]` is an empty list.
- Unknown is not available: a product or option with no availability signal
  is reported unavailable.
- Personal fields are not declared in the wire structs, so they are never
  decoded; errors carry no URL, header, token or response text.

`ApplyCart` follows the order: read the live basket, compare the live
`basketVersion` with the caller's `ExpectedVersion` (`NoBasketVersion` when
no basket should exist) and write nothing on a mismatch
(`precondition_failed`, `ErrPrecondition`), validate the selected options
against the live product view, write once, reread, and compare the reread
content with the requested change (`reconciled`, or `reconcile_mismatch`).
The write is never retried and never replayed after a 401. A 4xx is
`rejected` (`ErrWriteRejected`); a timeout, 5xx or dropped connection is
`reconcile_unknown` (`ErrWriteUnknown`), and the caller must read the cart
back. `Writer` is not a `glovoprovider.CartWriter`: the approval-grant and
fingerprint checks stay outside the adapter, so any caller must sit behind an
approval-bound wrapper. A line that appears twice with the same product and
options is refused before any write.

Unverified, because no real Glovo call can be made in this change: every wire
shape (field names come from upstream code and tests, not from recorded real
responses), whether the raw token (no `Bearer` prefix, as upstream) is what
the API expects, whether option payloads carry an availability flag, whether
line prices are line totals, the `/baskets` list shape, and whether a PUT
echoing the basket is accepted. The fixtures in `live/testdata` are
synthetic.
