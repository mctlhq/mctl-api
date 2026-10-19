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
| local OAuth JWT (GitHub callback) | `github` | — | its `pid` claim when it has one, else resolved from the login (see below) | human |
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
   names the principal **P**. A page then says what to enter at ZITADEL
   (the login name from the invitation e-mail, not the e-mail address and
   not the GitHub login) and links to the ZITADEL leg. Under
   `prompt=login` ZITADEL always asks for a name, and with
   `ignore_unknown_usernames` it answers an unknown one with a password
   page that a passkey-only account cannot pass. An e-mail address fails
   too: Login V2 v4.19.x opens the passkey session with it as a login
   name, which the API does not resolve (zitadel/zitadel#12852). See #462.
   The link carries this session's state, so step 3 checks it.
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
   unfinished links; a fourth drops the oldest one still waiting for
   GitHub, so no single source can fill the global cap of 1000. A link
   that has left for GitHub or proven an identity is never dropped (on a
   shared egress IP it is usually someone else's): when all 3 are past
   that point, the new start gets a 429. A sign-in cancelled or failed at
   either IdP ends its link at once, so it never holds a slot. With more than one replica, a step
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
holding live identities. It is also refused with 409
`principal_last_admin` when `from` is the last active `ADMIN_PRINCIPALS`
principal (the same check as a disable, below; `into` counts as the other
admin only when it is itself in `ADMIN_PRINCIPALS`). A retry is safe: when `from` is already disabled
with no live identity left, the answer is 200 with `already_merged: true`
and nothing changes. The store does not record which principal it went
into, so the answer carries a `detail` saying the earlier target may
differ from `into`; the audit rows record it. Every outcome, refusals included, is audited
with the actor, `from` and `into`.

A principal that must stop acting but that no merge can absorb is disabled
instead: `POST /api/v1/admin/principals/{id}/disable` with body
`{"reason": "..."}` (required, trimmed, at most 500 characters). The case it was
built for is an orphan whose only identity is a ZITADEL user removed at the
IdP: merging it into the admin's own principal is refused because both hold
a ZITADEL identity of the same issuer, and `DELETE /identity/links` acts on
the caller's own identities only. Same gate as a merge (a platform admin
acting directly; audit `principal.disable`, high risk). Every outcome after
the admin check, refusals included, is audited with the actor, the target,
the reason and, on failure, a classified `refusal`, never the store's error
text.

| Case | Answer |
|---|---|
| not a platform admin acting directly (relayed, surface, service, agent) | 403, not audited |
| missing or empty reason, unknown body field, malformed principal id | 400 |
| the admin's own principal did not resolve | 403 `actor_unresolved` (it cannot prove it is not the target) |
| the target is the caller's own principal | 409 `principal_disable_self` |
| no such principal | 404 |
| a service or agent principal | 400 `principal_not_human` |
| the last active `ADMIN_PRINCIPALS` principal | 409 `principal_last_admin` |
| store unavailable | 503 `identity_link_unavailable` |
| already disabled (a retry, or disabled by a merge) | 200, `already_disabled: true`, nothing changes |
| active human | 200, disabled |

The last-admin check runs in the same transaction as the update, under the
locks of the target and every other admin principal, so two admins
disabling each other at once cannot both succeed. A principal named in
`ADMIN_PRINCIPALS` that does not exist, is disabled, or is not human does
not count as another admin. With `ADMIN_PRINCIPALS` empty there is no
admin principal to protect and the check does not apply. A merge whose
`from` is an admin runs the same check under the same locks (#650), so a
merge and a disable of two admins at once cannot both succeed either. The
store's `SetStatus` enforces nothing and is used only by tests.

The principal's identities are left bound and live, not revoked:

- A disabled principal is already refused everywhere. Each of its
  identities resolves to `ErrPrincipalDisabled` at authentication, and a
  local access token naming it fails the principal check on use. Revoking
  would add no refusal.
- The binding keeps the identity from being provisioned onto a fresh,
  active principal at its next sign-in, and records who the principal was.
- A merge reads "disabled with no live identity" as "already merged away".
  Revoking here would make the disabled principal look merged, and a later
  merge from it would answer `already_merged` without moving anything.

Its local OAuth refresh sessions are revoked after the commit
(`sessions_revoked` in the answer), so they stop renewing. That step is
best effort: the principal is already refused on every token, so a failed
revocation leaves `sessions_revoked: null` and `sessions_revoke=failed` in
the audit row rather than failing the call. The resolver cache for the
target is dropped, also on a retry, so the disable takes effect on the next
request. There is no MCP tool for this; it is an HTTP admin operation only.

The resolver caches answers for 5 minutes, including the principal id and
its disabled flag. A merge, a disable and an unlink therefore drop the cached answers
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

## Signing in to MCP clients with ZITADEL (#467)

`OAUTH_UPSTREAM` decides where `GET /oauth/authorize` (every MCP connector)
signs people in: `github` (the default, unchanged), `zitadel`, or `both`
(a page offering ZITADEL first and GitHub as legacy; the choice comes back
as the same authorization plus `upstream=`).

### Customer entry: "Sign in with GitHub" (mctl-web#158)

A customer (ZITADEL organization `customers`, GitHub its only IdP) finds no
GitHub button on the instance login page. So when the ZITADEL entry has
`customers_org_id` and `ZITADEL_HOOK_GITHUB_IDP_ID` names that
organization's GitHub IdP (the identity hook's Secret carries both, and
`ZITADEL_HOOK_CUSTOMERS_ORG_ID` must equal `customers_org_id`), the chooser
gets a customer entry, `upstream=customer`, labelled "Sign in with GitHub":

| `OAUTH_UPSTREAM` | Chooser |
|---|---|
| `zitadel` | Sign in with GitHub (customers, new and returning), Sign in with MCTL account (staff and partner accounts) |
| `both` | the same two, then GitHub as legacy |
| `github` | no chooser, no customer entry |

The customer entry starts the same ZITADEL authorization with two more
scopes, `urn:zitadel:iam:org:id:<customers_org_id>` and
`urn:zitadel:iam:org:idp:id:<github idp id>`, exactly as mctl.ai does
(mctl-web `cloudflare-worker/zitadel.js`): ZITADEL signs the person in to
`customers` and goes straight to GitHub. The other entry, "Sign in with
MCTL account", is for everyone who already has a ZITADEL account in
another organization: staff and partner organizations alike, which is why
it does not say "staff". Such a person pressing "Sign in with GitHub" would
get a separate customers account, refused with `customer_conflict` because
their GitHub identity already belongs to their principal; that 409 page
points them to "Sign in with MCTL account". That entry and
the code exchange are unchanged. The choice is not stored with the pending
authorization: whether the person signs in as a customer is decided in the
callback from the verified ID token's organization (see "Self-service
customers" in `docs/federation.md`), so choosing the entry grants nothing.

It fails closed. Without both ids, or with the hook's organization unset or
different, no customer entry is offered and `zitadel` goes straight to
ZITADEL as before. An `upstream=customer` that is not offered answers 400
rather than becoming a staff sign-in; under `github` that includes a
request carrying `upstream=customer`, where `upstream=` was ignored
before. The 400 is a page, not an OAuth error to the client: only a
person on the chooser makes this choice. A `ZITADEL_HOOK_GITHUB_IDP_ID`
that is not a ZITADEL resource id (digits) is never offered, since it is
written into a scope string. It also refuses the boot where the entry
could be wired (a customers entry and `OAUTH_UPSTREAM` other than
`github`), unless `MCTL_FEDERATION_DISABLED` is on: like the other
`MCTL_OIDC_PROVIDERS` checks, the kill switch skips it so a rollback is
never blocked, and the entry is then just not offered. The startup log
line `OAuth ZITADEL upstream enabled` says `customer_github_signin=true`
when the entry is offered, and every ZITADEL sign-in whose verified token
names the customers organization is counted under
`oauth_upstream_signins_total{upstream="zitadel_customer"}`.

The ZITADEL leg uses its own confidential client
(`OAUTH_ZITADEL_CLIENT_ID` / `OAUTH_ZITADEL_CLIENT_SECRET`, not the link
client), redirect `<SELF_URL>/oauth/zitadel/callback`, PKCE S256 and a
nonce, and no `prompt=login`: an existing ZITADEL session is the single
sign-on this is for. The ID token is verified against the
`MCTL_OIDC_PROVIDERS` entry `OAUTH_ZITADEL_PROVIDER` (default `zitadel`)
with this client as audience, and `(provider, iss, sub)` is looked up
read-only (`Store.LinkedGitHub`):

| Lookup | Answer |
|---|---|
| linked to P, P has one live GitHub identity with a login | code for that login and P (`pid`): the same code, groups and admin decision (`ADMIN_USERS`) a GitHub sign-in of P yields; in `principal` mode no groups are minted |
| no row, or a principal of its own with no GitHub identity | 403 page linking to `/identity/link/zitadel`; nothing issued or provisioned. In `principal` mode: a code for the identity's own principal (provisioned on first sign-in), `sub` = `pid` = its principal id, with no groups; it reaches a tenant only once a GitOps member entry names that `principalId` |
| identity revoked, or P disabled | 403 |
| P's GitHub login unknown (taken by another account) or two live GitHub identities | 409, nothing guessed. In `principal` mode: a code for P with no login, as in the row above |
| store error, or no principal store | 503, never "not linked" |
| (`principal` mode) the principal resolver answers a different principal than the link store | 503 `store_unavailable`; nothing issued |

A pending authorization records its upstream: a GitHub callback cannot
complete a ZITADEL authorization or the reverse, and an authorization whose
upstream the current mode does not allow (one pending across a rollback)
gets a 400. Sign-ins are counted in
`oauth_upstream_signins_total{upstream,result}`. A sign-in whose verified
ID token names the customers organization is counted under
`upstream="zitadel_customer"`, refusals included (`customer_unproven`,
`customer_conflict`, `customer_not_enabled`, `principal_*`), so a hook or
claim-client misconfiguration shows there. A token that names no
organization cannot be placed and stays under `zitadel` as
`invalid_token`. Queries on `upstream="zitadel"` no longer see customer
sign-ins. For `upstream="zitadel"`,
`result` is `issued`, `unlinked`, `refused`, `store_unavailable`,
`principal_refused`, `principal_unavailable` (`principal` mode, as for GitHub),
`invalid_token`, `upstream_error` (ZITADEL redirected back with an error),
`upstream_unreachable` (discovery failed), `exchange_failed`,
`bad_request` or `internal_error`, so "ZITADEL is down" and "mctl is
broken" stay apart.

`zitadel` and `both` refuse startup when `OAUTH_JWT_SECRET`, the ZITADEL
client, or the provider entry is missing, when that entry keys identities
on a claim other than `sub` (links are written by `sub`), when
`OAUTH_ZITADEL_PROVIDER` differs from `ZITADEL_LINK_PROVIDER` (sign-in
reads links under the entry name linking writes them with), and, for `both`,
without the GitHub app. Under `zitadel` the GitHub app stays optional; the
link flow needs it, so without it linking answers 503. Rollback is
`OAUTH_UPSTREAM=github`.

`OAUTH_ZITADEL_REDIRECT_BASE_URL` is for local end-to-end runs only and is
never set in a deployment. When it is set, it replaces `<SELF_URL>` in the
redirect_uri sent to ZITADEL, for both the authorize request and the code
exchange. Nothing else changes: the issuer, the metadata and the client
callbacks stay on `SELF_URL`. This makes a local mctl-api behind a quick
tunnel workable. Clients reach the tunnel's random host, while the browser
comes back to `http://localhost:8080/oauth/zitadel/callback`, which a
dev-mode ZITADEL app can register once. The pending authorization is held
server-side, so no cookie has to cross from one host to the other. The value
must be a bare origin: https, or http on a loopback host. Anything else
refuses startup under every upstream.

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

Nothing reads the ids for a decision. Two payloads serve them
(mctl-api#376 slice D), and no other one does:

- The action approval, in every response that carries one (create, get,
  list, decision and consume under `/api/v1/action-approvals`), returns the four
  principal ids above, plus the requester as actor and subject:
  `actor_kind`, `actor_name`, `subject_principal_id`, `subject_kind` and
  `agent_run_id`. They are taken from authentication at create and stored
  in columns of the same names; a request body naming any of them is
  refused with `actor_not_accepted`. The decider is `decided_by` and its
  two principal ids.
- `GET /api/v1/identity/self` (below).

## Actor and subject: `GET /api/v1/identity/self`

Returns, in the `identity/v1` shape the policy checkpoint and the evidence
envelope read:

```json
{"schema_version": "identity/v1",
 "actor":   {"principal_id": "prn_…", "kind": "agent", "name": "implementer"},
 "subject": {"principal_id": "prn_…", "kind": "human", "name": "alice"},
 "execution_id": "we_…", "work_item_id": "wi_…", "agent_run_id": "art_…",
 "grant":   {"kind": "execution_request", "ref": "xr_…"}}
```

- The **actor** is the principal that authenticated: the agent run, the
  service, the surface or the human.
- The **subject** is the human the actor acts for, and is set only on a
  delegated request (an agent run token sending `X-MCTL-On-Behalf-Of`, which
  this route accepts) or a relayed one (a surface). Otherwise it is `null`,
  never a copy of the actor: `null` is the statement "acting for itself".
- `grant` is the delegation grant the gate resolved, and `null` unless the
  request is delegated. A relay is authorized by its surface link instead.
- On a delegated or relayed request the record columns keep their existing
  meaning: `actor_principal_id` (or `requested_by_principal_id`) holds the
  subject, and `via_principal_id` the agent or surface that carried it.

Every field comes from authentication and the delegation gate. Nothing is
parsed out of a principal string or a login, and the same human resolves to
the same `principal_id` whichever provider they signed in with.

## DevLoop approval by grant (#571)

A DevLoop's human approval is exercised by the agent run that waits for
it, as that human, through an action approval (`aar_`). Four parties stay
distinct: the **human** who decides (subject, a `prn_`), the **agent run**
that submits (actor, `agent:<name>` with its `art_` token), the run's
**execution** (`we_`, canonical; the Temporal workflow id is its
`engine_ref`), and the **grant** that links them (`aar_`).

1. The worker attaches its DevLoop to the issue's work item as a `we_`
   (`engine=temporal`, `engine_ref=<workflow_id>`, or
   `<workflow_id>#<request_id>` for a run dispatched from an execution
   request) and, at the approval gate, creates an `aar_` for that `we_`:
   action kind `mctl-agents-approve`, target `<service>/<slug>`, policy
   `dev-loop.human-approval`/`v1`. Creating it still takes the
   `mctl-agent` service token.
2. A human admin approves with
   `POST /api/v1/agents/dev-loop/{workflow_id}/approve`. The workflow id is
   resolved to its one open `we_` (more than one is 409
   `execution_ambiguous`), and the newest `aar_` of that kind for it, in
   any state, decides the answer: a pending one is decided and its
   `approval_ref` signalled, an approved and unspent one is signalled
   again, and a denied, consumed or expired one is refused with that
   state's 409 whatever the legacy flag says. No `aar_` (or no `we_`) is
   the legacy relay while `MCTL_AGENTS_APPROVE_LEGACY_APPROVER` is on and
   409 `approval_grant_missing` once it is off. A store error is 503
   `work_items_unavailable`, never "none".
3. The run calls `POST /api/v1/operations/mctl-agents-approve/execute`
   with its run token and `X-MCTL-On-Behalf-Of: aar_…`. The delegation
   gate binds the grant to the run's `we_` and takes the subject from the
   grant's `decided_by_principal_id`; the operation then checks the grant
   instead of the admin role, and spends it once
   (`ConsumeActionApproval`, an intent-hash compare-and-set) before
   anything is submitted. The recorded approver is the decider's name;
   the body may not name one. The workflow also receives
   `expected_content_digest` and `approval_ref` (the `aar_` id), both set
   by the server from the grant; `approval_ref` in a body is refused on
   every path.

The operation record carries `actor_kind=agent`, `actor_name`,
`agent_run_id`, `execution_id`, `subject_principal_id` and `grant_ref`, and
the audit trail has `action_approval.create`, `.decision` and `.consume`
(each with a `_refused` counterpart).

**Subject from the principal, for every IdP.** For an `xr_`, `aar_` or
`wi_` grant the subject is the principal the grant stored, checked active
on every request: a ZITADEL-only human approves the same way as a GitHub
one. A grant with no stored principal (an undecided `aar_`), or whose
principal is disabled, is 403 `grant_subject_unresolved`; it never falls
back to the login string. A `sil_` grant of a `github:<login>` link stores
no principal and still resolves through its mirrored GitHub identity, so it
requires a `github:` subject; it cannot authorize this operation. A `sil_`
grant of a `prn_` link (#646) carries the link's principal and is checked
like the other kinds. Binding a surface actor to a delegated subject
compares principals (#629, next section).

| Code | Status | Where | Meaning |
|---|---|---|---|
| `grant_not_bound` | 403 | gate | the `aar_` is for another `we_` or work item, or is denied, expired or consumed |
| `grant_subject_unresolved` | 403 | gate | no stored principal (undecided), disabled, or (`sil_`) a `github:` link without a GitHub subject or a `prn_` link without its recorded `oidc:` name |
| `actor_not_accepted` | 400 | operation | the body names an `approver`, `expected_content_digest` or `approval_ref` |
| `approval_intent_mismatch` | 409 | operation | another action kind, target or policy; a target that maps to no workflow id or not to the run's own DevLoop; or the approval's `we_` no longer exists |
| `approval_consumed` / `approval_expired` | 409 | operation, approve route | spent or past its expiry |
| `approval_executed` | 409 | approve route | the newest grant was spent and marked executed |
| `approval_denied` | 409 | approve route | the newest grant was denied |
| `approval_grant_missing` | 409 | approve route | no grant and the legacy flag is off |
| `execution_ambiguous` | 409 | approve route | more than one open `we_` for the workflow id |
| `legacy_approver_disabled` | 400 | operation | free-text `approver` from a service principal with the flag off |
| `approval_content_unbound` | 400 | operation | a non-grant approve without `expected_content_digest` (mctl-api#722); a service principal off the grant path always lands here or on `actor_not_accepted` |
| `approval_content_digest_malformed` | 400 | operation | a non-grant approve whose `expected_content_digest` is not `sha256:<64 lowercase hex>` |
| `delegation_unavailable` | 503 | gate | the grant could not be resolved (store outage) or delegation is not configured |
| `work_items_unavailable` | 503 | operation, approve route | a work-item store read failed, or (approve route, flag off) the store is not configured |

The target binding maps `<service>/<slug>` to a workflow id the way the
shepherd does (`temporalclient.WorkflowIDForProposalRef`), which keeps only
the slug's `issue-<n>-` prefix: it pins the service and the issue, and the
intent hash pins the exact slug.

**Retiring the legacy relay.** While the flag is on, the `mctl-agent`
service may still relay a free-text `approver`; every use writes one
`approver.legacy_relay` audit entry and increments
`mctl_agents_approve_legacy_relay_total{outcome="relayed"}`. The flag goes
off only after a full natural DevLoop cycle (the Saturday cron and one
issue-triggered loop) with mctl-agents#636 deployed records actor and
subject separately and zero legacy relays.

## Surface actors and human-input respondents by principal (#629)

Two human paths used to key on a verified GitHub login, which refused a
ZITADEL-only human (a principal with no single live GitHub identity). Both
now compare canonical principals.

**Binding a surface actor under delegation.** `POST
/api/v1/work-items/{id}/surface-refs` with a non-empty `actor_external_id`,
called by an agent run delegating as a human, binds that surface identity
to the work item (and with it the identity's `sil_` grant). The binding is
allowed only when the identity's live link resolves to the delegated
subject's principal. The subject's principal is the one the gate resolved:
for an `xr_`, `aar_` or `wi_` grant the stored `prn_`, whatever IdP the
human signed in with. The link's owner is read from the stored link, never
from the caller. A `github:<login>` owner is resolved through the principal
store exactly as the gate resolves a `sil_` subject, so the principal a
surface actor is bound for is the principal its `sil_` grant later acts as.
Like the gate, that lookup may ask GitHub for the login's id and provision
a principal for it, on this write path. A `prn_` owner (#646) is that
principal once the store confirms it is an active human (#663: the kind is
checked here too, although only a human can hold a `prn_` link). A subject that shares the
owner's login string but is another principal is refused.

| Outcome | Status | Code |
|---|---|---|
| the subject has no resolved principal | 403 | `grant_subject_unresolved` |
| another principal's identity; unknown, revoked or expired link; owner disabled or refused | 403 | `grant_not_bound` (one answer, no existence oracle) |
| the link store could not be read; the owner's login could not be resolved (unknown GitHub identity, GitHub or principal store unavailable); the principal store is not configured or cannot check a `prn_` owner | 503 | `delegation_unavailable` |

**Surface links for any human (#646).** A link names its holder in one of
two forms. A caller whose GitHub login authentication proved is linked as
`github:<login>`, as before. Any other human acting directly (a ZITADEL
sign-in, say) whose principal authentication resolved is linked as that
`prn_`, and the link records the name the human acted under, `oidc:<name>`
(`principalOf`), as its `subject`. A service, surface or agent, a relayed
or delegated subject get 403 `human_principal_required`. A human whose
principal authentication could not resolve because the principal store did
not answer gets 503 `surface_identity_unavailable` on challenge, list and
revoke instead (#663): that is "unknown", not "has no principal". A name the
link cannot record (a non-printable character, too long) is 403
`human_principal_required` and is logged.
A `prn_` link needs `TENANT_AUTHZ_MODE=principal`: its relayed subject's
tenants come from the principal, and only principal mode resolves them, so
outside it the challenge is 403 `principal_mode_required` rather than a link
every tenant-scoped relay would refuse. The relay checks the same thing on
every request (#663), because a link outlives a `TENANT_AUTHZ_MODE`
rollback and a challenge minted before one can still be redeemed after it:
a `prn_` link relayed outside principal mode is 403 `principal_mode_required`.

One human can sign in through GitHub and through ZITADEL onto the same
principal, and each session holds the other's links (#646, #663):

- the GitHub session also holds its resolved `prn_`;
- a `prn_` session also holds `github:<login>` for every live GitHub
  identity of its principal, read from the principal store. A revoked
  identity, or one whose login the store no longer knows (it moved to another
  GitHub account), holds nothing.

Either session lists both holders' links and may revoke them. Who the
session holds links as is never guessed: if the principal store cannot
answer (or, for a GitHub session, authentication could not resolve the
principal), the list is 503, not a shorter list, a list naming a holder
other than the session's own holder form is 503, not 403, and a revoke of a
link none of the known holders holds is 503, not 404. The session's own
holder form stays usable meanwhile (#671): its links can be listed by
naming it (`?principal=github:<login>` from a GitHub session,
`?principal=<prn_>` from a `prn_` session) and revoked, since that holder's
list is whole whatever the rest of the set is. An admin listing a named
holder, or revoking, needs no holder set at all. The derived
`github:<login>` matches a link's holder exactly (the store compares logins
case-insensitively); both are GitHub's spelling of the login, so they can
differ only across a case-only rename no sign-in has recorded yet. The list
response's `principal` is the holder form asked for, the session's own one
by default, `holders` every holder whose links are listed, and each link
names its own holder in `principal`. A new link for an identity already
held under the other form is still `link_conflict`; revoke the old one
first, from either session.

The audit keys naming the holder mean the same in every
`surface_identity.*` event: `principal` is the holder (`github:<login>` or
`prn_…`) and `holder_subject` the recorded `oidc:` name of a `prn_` holder.
`linked` and `revoked` also keep `subject`, which has always meant the holder
there. `challenge_created` carried the name as `subject` only in 4.95.0
(#660); it is `holder_subject` from the release after it, with no
transition period: the key shipped one day before the change.

- The mirror writes a `prn_` link's telegram identity for that principal
  outright. A `prn_` that does not exist or is not human fails the redeem,
  which is rolled back with the mirror.
- The relay runs as the link's principal, checked an active human on every
  request (`CheckPrincipal`, then `CheckHumanPrincipal`): disabled is 403
  `principal_disabled`, unknown, refused or not human 403 `identity_refused`,
  and a store that cannot answer is 503,
  never a relay without a principal. A `prn_` link without a well-formed
  `oidc:` subject is 403 `link_not_found`. The relayed subject acts under the
  recorded name, so what it writes is owned by the same `oidc:<name>` the
  human owns directly.
- The `sil_` grant and the surface-actor binding follow the principal, as
  above.

The recorded name is only a name: renaming the human in ZITADEL leaves the
link on the same principal, and the next possession proof records the new
name. Until then the relay acts under the old name, so items written through
the surface are owned by `oidc:<old name>` and are not visible to the human's
direct sessions under the new one. A direct sign-in does not refresh it
(deferred from #663): only a new possession proof does.

**Answering human input.** `requested_from.actor_refs` entries stay in the
`actor_type:actor_id` form that mctl-agents' `validate_response` rebuilds
from the signalled respondent. Besides `github:<login>`, an entry may now
name a principal as `principal:<prn_…>`. A caller may answer as:

1. `github:<login>`, when authentication proved that GitHub login;
2. `principal:<prn_…>`, the caller's resolved principal, for any IdP, and
   only for a human identity: a service, surface or agent principal never
   answers, even if `actor_refs` named it.

The respondent is the first of these that `actor_refs` names, matched
exactly. Both are derived from authentication; the body cannot name a
respondent. A caller whose principal is unresolved has no principal
reference, so it never matches one. The ledger row keeps
`respondent_principal_id` as before, and the audit `respondent` is the
reference answered as. Existing `github:` refs keep working during the
migration; mctl-agents writing `principal:` refs is its own change.

## Not in phase 1

Authorization and tenant membership still use `User.ID` and `User.Groups`,
and idempotency keys stay scoped to the actor strings. Switching them to
principal ids is phase 2 (#377), described next.

## Tenant membership by principal (#377)

GitOps member entries gain a `principalId`, which becomes the authorization
key; `userId` (a GitHub login) stays as optional display data:

```yaml
tenant:
  name: acme
  members:
    - userId: boss                              # optional, display only
      principalId: prn_01J00000000000000000000000
      role: owner
  teams:
    - name: web
      members:
        - principalId: prn_01J11111111111111111111111  # e.g. a ZITADEL-only user
          role: developer
```

Parser rules: `principalId` must match `^prn_[0-9A-HJKMNP-TV-Z]{26}$`; a
malformed value, the same `principalId` twice in one members list, or an
entry with neither key makes **that tenant** unreadable for principal-keyed
reads (an error, never "not a member"). The login-keyed path ignores
`principalId` entirely, so a bad key cannot change today's decisions. Team
and tenant-level semantics are the login ones; only the key differs.

New tenants are keyed from the start. `create-tenant` stamps
`creator_principal_id` from the session, like `creator_user_id`, and never
forwards a value from the request body. The workflow writes it as the owner
entry's `principalId`. A caller whose principal is unresolved is refused
with `503 creator_principal_unavailable` in every mode, admins included,
and nothing is submitted: the workflow pushes straight to gitops main, so a
login-only owner entry would land before CI
(`scripts/validate-tenant-member-keys.py`) could flag it.

The portal creates tenants without going through mctl-api: its `POST
/tenants` (the mctl.me signup form, the portal's own page, the Backstage
scaffolder) submits `create-tenant` itself and knows the creator only by
GitHub login. Before it does, it asks for the principal with `POST
/api/v1/surface-principals/github`, sending its surface token and
`X-MCTL-Surface-Actor: github:<login>` with no body. The route answers
`{"principalId": "prn_..."}`. It resolves the login the way a first sign-in
would: through the live GitHub identity that holds it, else GitHub's numeric
id, provisioning a principal if there is none. Only the portal surface may
call it (`403 portal_surface_required`). A disabled or refused identity
is `403`, and any other failure is `503`, never an empty answer; a login
GitHub does not know is a `503` too, since the resolver cannot tell it
from an outage. A resolution is audited as `principal.resolve_github`, a
resolver refusal as `principal.resolve_github_refused`; a `503` is
logged. This confers nothing new: the portal could already make any login
the owner of a new tenant.

A self-service customer (`docs/federation.md`, "Self-service customers") is
resolved by its ZITADEL ID token instead, with `POST
/api/v1/surface-principals/zitadel`, body `{"idToken": "...", "purpose":
"create" | "signin"}` and `X-MCTL-Surface-Actor: zitadel:<sub of the token>`.
mctl-api verifies the token itself: signature against the issuer's keys,
issuer, expiry, and that it was issued to the client the purpose names, both
as an audience and as `azp`: the mctl-web site's client
(`MCTL_WEB_CLIENT_ID`) for `create`, the portal's (`ZITADEL_PORTAL_CLIENT_ID`)
for `signin`. Any other client, the dev client included, is `401
id_token_invalid`; a purpose whose client is not configured is `503`. The
route answers `{"principalId", "githubId", "githubLogin"}`, keyed on the
GitHub id the token proved. A token of another organization is `400
not_a_customer`, an unproven customer `403 customer_unproven`, a conflict
`409 customer_conflict`, a disabled principal or refused identity `403`, a
failed read `503`. Only the portal surface may call it. Resolutions are
audited as `principal.resolve_zitadel` and refusals as
`principal.resolve_zitadel_refused`.

### `TENANT_AUTHZ_MODE`

| Value | Decides | Also |
|---|---|---|
| `legacy` (default, or unset) | the login, as before | nothing |
| `shadow` | the login, as before | computes the principal decision for the same request and compares |
| `principal` | the principal | the login, `ADMIN_USERS` and provider groups stop counting; see [`principal` mode](#principal-mode) |

Any other value refuses boot. Rollback is setting the value back; no data
moves in either direction.

Break-glass: if `principal` mode locks people out (a GitOps checkout that
stops refreshing, a broken tenant file), set `TENANT_AUTHZ_MODE=shadow` and
restart. Authorization goes back to the login immediately, and shadow keeps
reporting what principal mode would have decided.

In `shadow`, for each request of a human caller (direct, relayed or
delegated; service, surface, agent, CI and dev callers are not compared):

- the request's tenant set (`User.Groups` without `admins`, which every
  `HasTenantAccess` call reads) is compared with
  `TryNamespacesForPrincipal(prn)`;
- every `checkTenantRole` write compares the login decision (allow/deny)
  with the one `MemberRolesForPrincipal` would give. A legacy decision that
  itself failed (503) is not compared, nor is a caller that is a platform
  admin on both sides. One that is admin on only one side is compared,
  since that is where the switch changes the answer.

- platform admin is compared once `ADMIN_PRINCIPALS` is set: the legacy
  decision (the `admins` group) against membership of `ADMIN_PRINCIPALS`.
  Without it the comparison is skipped, since every admin would read as a
  diff. It needs no membership read, so it is still made when the tenant
  comparison is unresolved (a broken tenant file must not hide every
  `admin_mismatch`). Set `ADMIN_PRINCIPALS` in shadow before the switch so
  the window measures it, and make it list the principal of **every**
  `ADMIN_USERS` entry: until the two sets agree each such admin counts
  `admin_mismatch` on every request (and `role_mismatch` on writes), which
  is a configuration gap to reconcile before starting the clock, not a
  shadow finding.

### `ADMIN_PRINCIPALS`

Comma-separated principal ids. A malformed entry refuses boot in every mode
(a typo must not silently drop or add an admin). In `principal` mode it is
the **only** source of platform admin: `ADMIN_USERS`, the `admins` group, a
provider's group claim and a tenant named `admins` all stop counting
(`ADMIN_USERS` set alongside is only warned about, so rolling back to
`shadow` stays a one-value change). `principal` mode refuses to boot
without at least one admin, with `PRINCIPALS_DISABLED` on, or without the
principal store (`SURFACE_IDENTITY_DB_URL` or `AUDIT_DB_URL`).

### `principal` mode

After authentication and principal resolution the middleware replaces the
caller's authorization; it never merges with the legacy one:

- a human caller's tenants are exactly the GitOps tenants that list its
  principal (`members[].principalId`), and it is a platform admin only if
  its principal is in `ADMIN_PRINCIPALS` and it acts directly: a relayed
  or delegated caller is never an admin, whoever it acts for. No login is
  read. Membership of a tenant named `admins` grants nothing, exactly as
  in `legacy`: a platform admin reaches it as admin.
- a human whose principal did not resolve gets **503** with `Retry-After`,
  platform admins included: without a principal there is nothing to look
  up in `ADMIN_PRINCIPALS` either.
- a human whose membership could not be read (stale checkout, any tenant
  unreadable) gets **503** with `Retry-After`, never an empty or partial
  tenant set. A platform admin is the exception: it is served without
  tenant groups, since admin does not depend on membership.
- a caller whose identity cannot be recorded at all gets **503** too.
- the static service principal and the dev caller (`AUTH_REQUIRED=false`)
  stay platform admins; every other non-human caller (surface, agent, CI,
  federated machine identity) holds no groups.
- `checkTenantRole` reads the role GitOps writes for the principal
  (`MemberRolesForPrincipal`); a non-human caller holds no tenant role, and
  an unresolved principal is 503.
- membership and roles are read from a snapshot of the tenants, built by
  each successful GitOps sync before it releases the checkout, never from
  the checkout on the request: a refresh holds the checkout across
  `git fetch`, and no request waits for it. A snapshot whose read hit an
  I/O error is not kept, so the next request reads again rather than
  answering 503 until the next sync. The snapshot's age is that of its own sync, so a
  snapshot older than `CheckoutMaxAge` answers 503 even when a later sync
  has landed but not yet been read. `membership_busy` (shadow) means a
  refresh held the checkout before any snapshot existed, i.e. only at
  startup.
- a human a surface relays for, or an agent run delegates to, gets the
  tenants of its own principal through the same decision as a direct
  caller, never those of its login, and is never a platform admin. One
  whose principal or membership cannot be read is refused with 503
  (`surface_identity_unavailable` / `delegation_unavailable`)
  rather than carried with no tenants: a relay no longer proceeds without
  a principal id in this mode.
- a platform-skill role binding on `admins` means platform admin, never a
  tenant named `admins`.
- `/whoami` reports `admins` in `namespaces` for a platform admin, but
  never in `groups`: admin is decided by principal, not carried as a
  group. Clients must read `isAdmin`, not `groups.includes("admins")`.
- `/whoami` `id` is the GitHub login for a GitHub-linked caller, but the
  principal id (`prn_…`) for a ZITADEL-only principal, which has no login.
  Clients must not treat `id` as a GitHub login (link to a profile, look it
  up in a repo's collaborators).

### Local tokens carry the principal (`pid`)

Every local OAuth JWT and refresh token now records the principal it was
signed in for, in every mode: a GitHub sign-in resolves it from the
numeric GitHub id, a ZITADEL sign-in from the linked identity. The access
token carries it as the `pid` claim; the refresh token row as
`principal_id` (`oauth_refresh_tokens`, added in place), and every
rotation carries it forward.

- A sign-in whose principal is disabled or refused gets a 403 page in every
  mode. Any other resolution failure mints without a principal outside
  `principal` mode, and answers 503 in it. A GitHub sign-in stopped either
  way is counted as `oauth_upstream_signins_total{upstream="github"}` with
  `result` `principal_refused` or `principal_unavailable`.
- In `principal` mode the `pid` is **checked** on each request (exists,
  not disabled), never re-derived from the login. Outside it the principal
  is still resolved from the login as before, and a `pid` that names a
  different one is counted in `oauth_token_principal_mismatch_total`,
  which must stay at zero before the switch.
- A principal with no GitHub login gets a token whose `sub` is its
  principal id. GitHub logins cannot contain `_`, so such a `sub` never
  reads as a login. The identity namespace `principal` is reserved: only
  the local OAuth provider may return it.
- In `principal` mode a token without a `pid` is refused (401), a
  principal-only token must have `sub == pid`, and a refresh of a session
  with no recorded principal answers `invalid_grant`. Outside it, a
  principal-only token is refused (401), and a refresh of a session with
  no login (a ZITADEL-only principal) answers `invalid_grant`.

At the switch, sessions minted before this release carry no `pid`, so
their holders sign in again. With the persistent refresh store the refresh
token is rotated before its missing `pid` is refused, so a client that
retries it gets `invalid_grant` and, once the rotation grace window has
passed, trips reuse detection: the family is revoked and `oauth refresh
token reuse detected; family revoked` is logged as a warning. On switch day
those warnings are pre-#377 sessions, not stolen tokens. A rollback out
of `principal` mode does the same to ZITADEL-only principals: their
sessions have no login, so their refresh is refused, and the same
reuse-detection warnings follow.

A disabled principal, merged-away ones included (a merge disables `from`),
is refused on every request. An **unlink is not**: the principal stays
active. What ends a session signed in through the unlinked identity is
that the unlink revokes **every** refresh session of the principal, in
every client, by `principal_id`. A refresh session does not record which
identity signed it in, so the unlinking user is signed out everywhere and
signs in again through an identity that is still linked. An unlink that
would be refused (an id that is not the caller's: 404; the last live
identity: 409) is refused before anything is revoked. Otherwise the
revocation runs before the unlink, so a failure answers 503 with nothing
unlinked and the request can be retried, and again after it, for a
session that rotated in between. The `identity.unlink` audit entry
carries `sessions_revoked` (sessions, i.e. refresh families, not rows),
`sessions_revocation` (`complete`, or `incomplete` when the second pass
failed) and `already_unlinked` (`true` for a repeated unlink, which
unlinks nothing but still ends the sessions, so a retry completes an
`incomplete` one); if the store still refuses after the check (a concurrent
change), a `failed` entry records the sessions already revoked and
`refused`. Access tokens already issued stay valid
until they expire (`OAUTH_TOKEN_TTL`); nothing re-checks the identity at
refresh, so the revocation is what stops the renewal.

### Metrics

| Metric | Meaning |
|---|---|
| `tenant_authz_shadow_total{result}` | `match`, `diff` or `unresolved` per comparison |
| `tenant_authz_shadow_diff_total{kind}` | `tenant_only_legacy`, `tenant_only_principal`, `role_mismatch`, `admin_mismatch` (only with `ADMIN_PRINCIPALS` set) |
| `tenant_authz_principal_unresolved_total{reason}` | `no_pid` (no principal at authentication), `membership_busy` (no membership snapshot yet and a refresh holds the checkout: startup only), `membership_unreadable` (stale checkout, or any tenant unreadable; on the role path also no snapshot yet while a refresh holds the checkout, which the membership path counts as `membership_busy`), `membership_unavailable` (reader not wired) |
| `tenant_member_entry_unkeyed{tenant}` | member entries with no `principalId` |
| `tenant_principal_keys_invalid{tenant}` | 1 when a tenant's keys are invalid or the tenant cannot be read |
| `tenant_principal_keys_scan_ok` | 1 when the last scan could list the tenants; the two gauges above are cleared when it is 0 |
| `oauth_token_principal_mismatch_total` | local tokens whose `pid` names a different principal than the one resolved from the login (outside `principal` mode, where it is still resolved) |
| `oauth_upstream_signins_total{result}` | also `principal_refused` (disabled or refused principal, 403) and `principal_unavailable` (could not be resolved, 503 in `principal` mode), for both upstreams |

An `unresolved` comparison is never counted as a `match` or a `diff`: a
decision that could not be computed is not evidence either way. The one
exception is `admin_mismatch`, which needs no membership read and is
counted even when the tenant comparison was unresolved, so a broken tenant
file cannot hide it. `sum(tenant_authz_shadow_diff_total)` can therefore
exceed `tenant_authz_shadow_total{result="diff"}`. The
counters carry every diff; the log (`tenant authz shadow diff`, with the
path or tenant, the principal, the login and both decisions) carries one
line per distinct diff per 10 minutes, so it names the affected callers but
does not count them. The switch criterion reads the counters, never the log.

### Switch criterion

At least 7 consecutive days in `shadow` with: `tenant_authz_shadow_diff_total`
not increasing; `tenant_authz_shadow_total{result="unresolved"}` not
increasing for human callers; `sum(tenant_member_entry_unkeyed) == 0`,
`sum(tenant_principal_keys_invalid) == 0` and `tenant_principal_keys_scan_ok
== 1` throughout; and traffic seen through each sign-in path (GitHub PAT,
ZITADEL MCP OAuth, ZITADEL bearer). A window in which a path saw no traffic
does not count for that path.

Up to and including 4.86.0, the roadmap-state Reader also published the three key gauges
from a checkout with no tenants directory, so `tenant_principal_keys_scan_ok`
dropped to 0 for a few seconds after each of its refreshes and the
per-tenant series were briefly cleared. Zero samples from that cause are an
artefact, not a failed scan: count the `scan_ok` part of the window from the
release that fixed it.

Over the same window, `oauth_token_principal_mismatch_total` must stay at
zero. Before the flip, check pid coverage too: a live session with no
recorded `pid` (one minted before the release that started recording it)
is refused at the switch, and its holder must sign in again. A refresh carries an empty `principal_id`
forward, so such sessions end only by expiry or a new sign-in; count the
live refresh rows with an empty `principal_id` and decide whether that
many re-sign-ins are acceptable on switch day.

### Backfill plan

`GET /api/v1/admin/tenant-members/principal-plan` (platform admin acting
directly) proposes a `principalId` for every member entry and changes
nothing: no principal is provisioned and no file is written. A login is
resolved through the numeric id GitHub reports for it now, then the live
`external_identities` row; never through the login string alone.

Each entry gets a `status`: `keyed` and `propose` are fine; `unresolved`
(with a `reason`: `github_lookup_failed`, `no_linked_identity`,
`identity_revoked`, `principal_disabled`, `principal_not_found`,
`store_error`), `mismatch` (the key and the login name different principals),
`unverified` (a key whose `userId` could not be resolved, so the two were
never compared; retry) and `invalid` block. An unreadable tenant or a tenant key error also blocks.
`complete` is true only with zero blockers; the output then becomes a
human-reviewed mctl-gitops PR adding the keys.

### Complete customer-account deletion

`mctl_delete_tenant` preserves workspace-only deletion by default. A direct
human platform administrator may explicitly set `delete_customer_account=true`
and provide the exact `customer_principal_id`. The customer must be the sole
principal-keyed owner with no other tenant/team membership. The API freezes an
immutable manifest before any GitOps removal; callbacks cannot choose a fresh
subject by display login. Failed observations remain retryable errors.

`CUSTOMER_DELETION_ENABLED=true` requires the lifecycle machine credentials,
configured ZITADEL provider, portal cleanup endpoints and pinned Worker identity.
`CUSTOMER_DELETION_SITE_URL` overrides the production website default for other
environments. Ordinary workspace deletion remains available without this flag.
The workflow disables credentials, removes resources, deletes the customer IdP
user and application sessions, purges active identity data, and releases the
portal name only after all postconditions pass. Historical audit and the
revocation manifest remain for safe retries and old-subject refusal.

Revocation intentionally adds an uncached indexed tombstone lookup to principal
authentication and credential minting. A warm API replica must refuse a deletion
begun by another replica immediately; a negative TTL cache would allow deleted
credentials for its lifetime. A configured-but-unavailable store therefore
fails authentication closed. Deployments that deliberately disable principals
or have no principal database retain the pre-existing signup behavior while
full deletion is disabled. Measure these indexed reads before replacing this
contract with a distributed invalidation mechanism; do not silently add a
negative-cache grace period.


The final portal release is acknowledged durably as `released_at`. Both the
GitHub creation probe and API administrator/MCP tenant creation keep the name
frozen until that acknowledgment is recorded, even after principal removal has
committed. A failed final acknowledgment is retried against the completed old
manifest; it does not rerun resource deletion or touch a replacement principal.

The immutable approved manifest fences the principal and old subject immediately
at `prepared`, before workflow submission or its `begin` callback. This prevents
a still-active customer from creating another workspace while submission is
retrying or the workflow is queued. The same uncached cross-replica checks apply
to existing API tokens and fresh token issuance. Database credential revocation
still runs idempotently in `begin`; the earlier deny fence must never wait for it.

Prepared cancellation uses `mctl_cancel_customer_deletion` with the exact tenant,
principal and explicit confirmation. Only a direct human platform administrator
may invoke it. Prepare, cancel and workflow callbacks share the cross-replica
run lock. Cancellation stamps `cancelled_at` on a prepared intent first, making
queued begin refuse and restoring the old principal/subject. Its exact identity
fields and tenant-name fence remain durable until the portal acknowledges and
the cancellation receipt can be removed. If the portal or final local
acknowledgment is unavailable, retrying the same cancellation completes it. A deleting/complete manifest is never
removed or reactivated; cancellation never restores independently removed
workspace resources. Historical cancellation/denial audit entries are retained.

Disabling `CUSTOMER_DELETION_ENABLED` stops new deletion preparations. Already
approved callback recovery and prepared cancellation remain configured so a
rollout rollback cannot strand an existing customer fence.

The external-effects run lock is tenant-keyed, including across successive
principal owners. A cancellation retry with no matching receipt must observe that no other
unreleased deletion holds the tenant name (unreadable is 503, another owner 409).
An absent pair performs no portal mutation: it confirms the desired final state,
not evidence that such a deletion previously existed.

Before `begin` disables credentials, it rechecks under the principal lock that
exactly the approved live GitHub and ZITADEL identities still belong to that
principal. An administrator merge/relink during the queued interval refuses
begin without touching the new identity owner; the prepared intent remains
cancellable. Once disabled, existing identity-mutation rules prevent moving its
live identities while the teardown continues.

Live and revoked surface mirrors are account-owned data, not extra authentication
providers. Prepare and begin use the same identity reader: it permits only
mirrors proven by surface_identity_links for the exact principal or its current
verified GitHub alias, and still requires the two exact live authentication
identities. Unproven/unrelated identities refuse deletion; read failures are
unknown. Tests drive CreateChallenge/Redeem/Revoke with the real principal mirror,
including a redeem between prepare and begin, complete cleanup isolation and
relinking after fresh signup. The active GitHub unique index excludes cancelled
receipts; startup migrates the old index under a cross-replica schema lock.
