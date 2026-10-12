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

## Signing in to MCP clients with ZITADEL (#467)

`OAUTH_UPSTREAM` decides where `GET /oauth/authorize` (every MCP connector)
signs people in: `github` (the default, unchanged), `zitadel`, or `both`
(a page offering ZITADEL first and GitHub as legacy; the choice comes back
as the same authorization plus `upstream=`, a parameter only `both` reads).

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
`oauth_upstream_signins_total{upstream,result}`. For `upstream="zitadel"`,
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

### `TENANT_AUTHZ_MODE`

| Value | Decides | Also |
|---|---|---|
| `legacy` (default, or unset) | the login, as before | nothing |
| `shadow` | the login, as before | computes the principal decision for the same request and compares |
| `principal` | the principal | **not yet accepted**: refused at boot until the last PR-B slice (local JWT `pid`, relayed and delegated callers) lands |

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
  principal-only token is refused.

At the switch, sessions minted before this release carry no `pid`, so
their holders sign in again. With the persistent refresh store the refresh
token is rotated before its missing `pid` is refused, so a client that
retries it gets `invalid_grant` and, once the rotation grace window has
passed, trips reuse detection: the family is revoked and `oauth refresh
token reuse detected; family revoked` is logged as a warning. On switch day
those warnings are pre-#377 sessions, not stolen tokens.

A disabled principal, merged-away ones included (a merge disables `from`),
is refused on every request. An **unlink is not**: the principal stays
active, and a session signed in through the unlinked identity keeps acting
as that principal through every refresh until its refresh family expires
(`OAUTH_REFRESH_TOKEN_TTL`, 30 days by default) or is revoked. Nothing
re-checks the identity at refresh. Revoking refresh families by
`principal_id` on unlink (the column is indexed for it) must land before
the switch.

### Metrics

| Metric | Meaning |
|---|---|
| `tenant_authz_shadow_total{result}` | `match`, `diff` or `unresolved` per comparison |
| `tenant_authz_shadow_diff_total{kind}` | `tenant_only_legacy`, `tenant_only_principal`, `role_mismatch`, `admin_mismatch` (only with `ADMIN_PRINCIPALS` set) |
| `tenant_authz_principal_unresolved_total{reason}` | `no_pid` (no principal at authentication), `membership_busy` (checkout held by a refresh), `membership_unreadable` (stale checkout, or any tenant unreadable), `membership_unavailable` (reader not wired) |
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

Over the same window, `oauth_token_principal_mismatch_total` must stay at
zero. Before the flip, check pid coverage too: a live session minted
before the release that records `pid` is refused at the switch and its
holder must sign in again. A refresh carries an empty `principal_id`
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
