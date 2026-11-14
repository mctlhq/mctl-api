# Glovo basket join API

The mctl-api side of the Glovo basket service split. A separate basket
service (the future `mctl-glovo` basket MCP) calls two routes under
`/api/v1/assistants/glovo-basket/v1` on behalf of one end user. The approval
page, the ledger, the allowlist and the team grants stay in mctl-api: the
service can resolve who the user is and ask for an owner approval of a frozen
basket revision, and nothing else. It never decides one.

Everything is dark: nothing here changes production until the flag below is
set.

## Routes

| Method and path | Purpose |
| --- | --- |
| `POST /resolve` | the end user's resolved scope: `principal_id`, `tenant`, `role`, `can_decide`, `subject_expires_at` |
| `POST /approvals` | creates (or returns) the pending owner approval of one basket revision |

The caller is the basket service's own identity (bearer token). The end user's
Glovo-audience access token arrives in `X-Mctl-Subject-Token`, header only; a
token in the query string is refused. Each request, with no cache:

1. verifies the subject token (signature, Glovo audience only, expiry,
   selected-tenant header compare-only), exactly as the Glovo join facade does
   (`glovojoin.VerifySubjectToken`);
2. checks the token's principal against the principal store
   (`auth.AttachPrincipal`): disabled or refused is 401, a store that does not
   answer is 503;
3. runs `scope.Resolve`: kill switch, team grant, live membership, pilot
   allowlist. A revoked grant or a removed allowlist row refuses the very next
   request; a failed read is 503, never a refusal and never "allowed".

`/resolve` takes an empty body or `{}`. `can_decide` reports whether the
user's role meets the approval page's decider role (`developer`); it is
informational, the page re-checks everything when a human decides.

`/approvals` takes:

```json
{
  "basket_id": "gbk_...",
  "revision": 2,
  "basket": { "v": "mctl-approval-basket/v1", "...": "..." },
  "item_names": { "FAKE-1": "display name" },
  "basket_fingerprint": "sha256:... (optional, compared only)"
}
```

There is no tenant or owner field: both come from the resolved subject.
mctl-api parses the basket against the vendored `mctl-approval-basket/v1`
schema, canonicalizes it (RFC 8785) and computes the fingerprint itself. A
`basket_fingerprint` sent by the caller is only compared: a value that
differs is `409 fingerprint_changed` and nothing is written. It is never
stored. The response is the approval reference, the fingerprint mctl-api
computed, the state, the expiry and `approval_url` on the approval page (201
when created, 200 when the same revision was already requested).

While the binding's foreign key into `glovo.basket_revisions` exists (it is
kept in this phase), the revision must also be one mctl-api stores for that
owner with that fingerprint; otherwise the answer is `fingerprint_changed`.

Limits: 60/min per subject, 10 approval writes/min per subject, 600/min in
aggregate. The global 300/min per-principal limiter is skipped for the basket
service, whose one id stands for every end user.

## Dark by construction, fail closed

The routes are mounted only when all of these hold; otherwise the prefix is
404 for everyone, the service included:

- `GLOVO_BASKET_JOIN_ENABLED` is exactly `true`. Unset or `false` is off; any
  other value is off with an error in the boot log (never a refused boot,
  never "on");
- `GLOVO_BASKET_JOIN_SERVICE_PROVIDER` names the federated OIDC provider
  (`MCTL_OIDC_PROVIDERS`, kind `service`) of the basket service, and is not a
  built-in namespace (`github`, `service`, `agent`, `principal`, ...);
- `GLOVO_BASKET_JOIN_SERVICE_SUBJECT` is the service's subject at that
  provider;
- the basket MCP is on (`GLOVO_BASKET_MCP_ENABLED`), which brings the store,
  the resolver and the schema checks.

Mounted, `glovoBasketJoinGate` confines the surface both ways: the basket
service (that provider and subject, kind service, no customer binding)
reaches only this prefix, every other path is 401; every other caller on the
prefix is 401. `isGlovoOwnerCandidate` refuses any non-human identity, so the
service can never decide an approval on the page or the action-approvals API.

## Frozen snapshot on every binding (basket schema 2)

`glovo.basket_approval_bindings` gains `snapshot_canonical` (the canonical
basket bytes) and `snapshot_lines` (the priced, named lines the owner is
shown). A CHECK (`basket_approval_bindings_snapshot_chk`) holds every row to
a snapshot whose SHA-256 is the binding's fingerprint, with 1 to 30 lines.
This makes a binding self-contained, so its foreign key into
`basket_revisions` can be dropped in a later phase; this phase keeps it.

- The in-process basket MCP writes the snapshot itself once the database is
  at basket schema 2. Against schema 1 it writes what it always did.
- A `BEFORE INSERT` trigger fills a missing snapshot from the matching
  revision, so an older binary keeps working against schema 2.
- Upgrading a database to schema 2 backfills every existing binding from its
  revision inside the migration transaction (the insert-only guard is lifted
  only there, under the table lock, and re-enabled before commit).

The binary accepts basket schema 1 and 2 at boot, so the deploy and the
migration can happen in either order. `/approvals` answers `not_ready` until
the database is at schema 2.

The schema is applied by `glovo-migrate` (step `basket-v2`, formerly
`basket-v1`) under the migration role; DDL never runs on the runtime role or
at boot.

Not in this phase: reading the approval page's payload from the snapshot
instead of `basket_revisions`, and dropping the foreign key.
