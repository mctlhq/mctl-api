# Canonical principals (phase 1)

mctl-api#373. Decision record: the owner-approved comments on that issue
(D1–D3, 2026-09-23, and the phase-1 decisions, 2026-09-24).

Where the `(provider, issuer, subject)` identity below comes from is a
separate boundary, the federation registry: see
[docs/federation.md](federation.md) (mctl-api#374). This model, and the
resolution rules below, are unaffected by that registry — it only decides
which verifier proves a token; `auth.Identity`, `PrincipalResolver` and
everything in this document stay exactly as they are.

## Model

- **`principals`**: `id` (`prn_<ulid>`, issued by mctl-api), `kind`
  (`human` | `agent` | `service`), `display_name`, `status`
  (`active` | `disabled`), `created_at`.
- **`external_identities`**: `id` (`xid_<ulid>`), `principal_id`, `provider`,
  `issuer`, `subject`, `display`, `verified_at`, `revoked_at`, with
  UNIQUE(`provider`, `issuer`, `subject`).

| Caller | provider | issuer | subject | kind |
|---|---|---|---|---|
| GitHub token | `github` | — | numeric GitHub user id | human |
| local OAuth JWT (GitHub callback) | `github` | — | resolved from the login, see below | human |
| Dex JWT | `dex` | token `iss` | token `sub` | human |
| `MCTL_AGENT_SERVICE_TOKEN` | `service` | — | `mctl-agent` | service |
| surface token | `service` | — | `surface:<name>` | service |
| agent run token (mctl-api#376) | `agent` | — | `agent:<name>` | agent |
| dev mode (`AUTH_REQUIRED=false`) | `dev` | — | `dev-user` | human |
| surface link (mirror) | `<surface>` | — | the surface-native id | — (the linked human's) |

`display` is informational: a GitHub login, a Dex `preferred_username`. It
never decides which principal an identity belongs to. The one use of a login
is for a caller whose GitHub login was proven without its id (a local OAuth
JWT, a relayed human): it maps through the live GitHub identity that
currently holds that login, or asks GitHub (`GET /users/{login}`) for the id.
A login belongs to one GitHub identity at a time: when GitHub reports it for
a different id, the older row stops answering for it.

## Resolution (every authenticated request)

- A new identity is provisioned on first sight: a new principal plus its
  identity, idempotent under concurrency. Never linked by spelling: a Dex
  user named like a GitHub login is a different principal.
- A **disabled** principal is refused at authentication (403). A **revoked**
  identity is refused (401), never given a new principal. A surface relaying
  for such a human gets 403 `principal_disabled` / `identity_refused`.
- The dev identity is refused unless `AUTH_REQUIRED=false`.
- Resolution is cached for 5 minutes.
- **Store unavailable** (or GitHub unreachable for a login lookup): the
  request proceeds without a principal id, logged and counted as
  `principal_resolution_failed_total`. A resolution is bounded at 3 s, so a
  store that is slow rather than down degrades the same way, and a failure
  is remembered for 5 s so a stalled store does not cost every request the
  full 3 s. Phase 2 fails
  closed instead.

## Surface identity links: mirrored, not replaced

`surface_identity_links` stays the source of truth for challenge → redeem
and for a link's expiry. A redeemed link is written to
`external_identities` (`provider=<surface>`) for the linked human in the same
transaction; a revoked link sets `revoked_at` there. A failed mirror rolls
the redeem back. That is why both live in one database
(`SURFACE_IDENTITY_DB_URL`, else `AUDIT_DB_URL`). A surface may not be named
after an authentication provider (`github`, `dex`, `service`, `dev`): its
mirror rows would collide with real identities.

## Linking a ZITADEL identity (#435)

A ZITADEL login seen for the first time becomes a **new** principal, like
any unknown identity. Attaching it to the principal a person already has
(their GitHub one) is an explicit act, never a match on a name or an
e-mail:

1. `GET /identity/link/zitadel` in a browser. mctl-api sets an httpOnly,
   Secure, SameSite=Lax `__Host-` cookie with a random value (it keeps only the
   SHA-256) and sends the browser to GitHub through its own OAuth app; the
   registered `/oauth/github/callback` recognises the `link.` state.
2. GitHub proves identity #1 (numeric id); it is provisioned as usual and
   names the principal **P**.
3. ZITADEL proves identity #2: authorization code with the confidential
   client `ZITADEL_LINK_CLIENT_ID` / `ZITADEL_LINK_CLIENT_SECRET`, PKCE
   S256, `state`, `nonce`, `prompt=login` and `max_age=0` (which makes
   `auth_time` a required claim). The ID token must carry the nonce and an
   `auth_time` inside this session. Its `iss` and `sub` form
   the identity, under the name of the `MCTL_OIDC_PROVIDERS` entry
   `ZITADEL_LINK_PROVIDER` (default `zitadel`), so later ZITADEL tokens
   resolve to it.
4. A confirmation page shows both identities; its POST carries a CSRF
   token tied to the session. Every step also checks the cookie, so a link
   started in one browser cannot be finished in another, and each step is
   single-use. Sessions live in memory for 10 minutes, counted from the
   start and checked again after every network call (one replica; a
   restart cancels links in flight). One source IP holds at most 3
   unfinished links; a fourth drops its oldest, so no single source can
   fill the global cap of 1000. With more than one replica, a step
   that reaches a pod other than the one that started the link gets a 400
   "start again", never a 500 or a link.

   The `link.` prefix keeps the two users of `/oauth/github/callback`
   apart in both directions: login states are base64url (no `.`) and go to
   the OAuth server; link states go to linking before the OAuth server
   looks anything up. Link states are bound to the cookie and single-use;
   login states are single-use and bound to the MCP client by PKCE.

Outcomes (`identity_links_total{provider,result}`, audit `identity.link`):

| State of the ZITADEL identity | Result |
|---|---|
| unknown | linked to P |
| already on P | `already_linked` (verified_at refreshed) |
| revoked on P | refused; only an operator restores it |
| on another principal Q | refused, 409 `identity_belongs_to_other_principal`, naming Q |
| P holds a different live ZITADEL identity | refused, 409 `principal_already_linked` |

Self-service never moves an identity between principals (owner decision on
#435). An admin merges instead: `POST
/api/v1/admin/principals/{from}/merge-into/{into}` (human admin acting
directly; audit `principal.merge`, high risk, with a classified `reason`
on failure) moves every live identity of `from` onto `into` and disables
`from`, which is kept because audit rows reference it; revoked identities
stay on `from`, and `moved_identities` counts live ones only. It is refused
when both hold a live identity of the same provider and issuer, or either
is not human, or `into` is disabled, or `from` is disabled while still
holding live identities. A retry is safe: when `from` is already disabled
with no live identity left, the answer is 200 with `already_merged: true`
and nothing changes. The store does not record which principal it went
into, so the answer carries a `detail` saying the earlier target may
differ from `into`; the audit rows record it. Every outcome, refusals included, is audited
with the actor, `from` and `into`.

The resolver caches answers for 5 minutes, including the principal id and
its disabled flag. A merge and an unlink therefore drop the cached answers
for the principals involved (`Resolver.Forget`), so the next request
re-reads the store: moved identities act as `into`, and an unlinked one is
refused. A resolution already reading the store when that happens returns
its answer once but does not cache it, so it cannot write the pre-change
answer back. This reaches the process that served the call, which is all of
mctl-api while it runs one replica; with more replicas the others would
keep their cached answer for up to the TTL.

`GET /api/v1/identity/links` lists the caller's identities; `DELETE
/api/v1/identity/links/{id}` revokes one of them (never the last live one;
a revoked identity is refused at authentication from the next request).
Both answer the person only: relayed (surface) and service callers get 403. Without the link client
the browser flow answers 503; without the principal store the API answers
503 too.

Proof of identity #1 is GitHub only for now; a Dex principal links through
GitHub or not at all.

## Backfill

Runs automatically after the first successful gitops sync, on every start,
and is idempotent. Source: gitops tenant and team members. For each login
without a live GitHub identity it looks up the numeric id and provisions a
human principal, then mirrors every live surface link whose human is now
known. `audit_events.user_id` is never a source: it carries no provider, so
a Dex username there is indistinguishable from a GitHub login.

## Dual-write

New records carry the principal id next to the string they already store.
On a relayed request the actor is the linked human and `via_principal_id`
is the relaying surface's service principal. A column stays `''` when the
principal could not be resolved (see degradation above) and on rows written
before this change; nothing is backfilled into them.

| Table | String column(s) | Principal id column(s) |
|---|---|---|
| `work_items` | `owner_principal` | `owner_principal_id` |
| `work_item_events` | `actor_principal`, `acting_principal` | `actor_principal_id`, `via_principal_id` |
| `work_item_intents` | `actor_principal` | `actor_principal_id` |
| `work_item_execution_requests` | `requested_by`, `acting_principal`, `claimed_by` | `requested_by_principal_id`, `via_principal_id`, `claimed_by_principal_id` |
| `action_approval_requests` | `requested_by`, `decided_by` | `requested_by_principal_id`, `via_principal_id`, `decided_by_principal_id`, `decided_via_principal_id` |
| `audit_events` | `user_id` | `user_principal_id`, `via_principal_id` |
| `human_input_deliveries` | `respondent` | `respondent_principal_id`, `via_principal_id` |
| `lifecycle_events` | (`actor_type`/`actor_id` name the owner, not the caller) | `caller_principal_id`, `via_principal_id` |

The ids are written only: no API response serves them yet and nothing reads
them for a decision.

## Not in phase 1

Authorization and tenant membership still use `User.ID` and `User.Groups`,
and idempotency keys stay scoped to the actor strings. Switching them to
principal ids is phase 2 (#377).
