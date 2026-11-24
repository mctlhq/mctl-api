# Glovo link consent (C2-1c)

mctl-api keeps each principal's consent to link a real Glovo account, and
serves it to mctl-glovo. This is slice C2-1c of mctlhq/mctl-glovo epic #11
(mctl-glovo `docs/design/token-store.md` 4.1 step 1, and
`real-glovo-accounts.md` 9.2 and 9.4 step 1).

## Record

Table `glovo_link_consents`, created idempotently by the store at start (the
repository's migration convention):

| column | meaning |
|---|---|
| `consent_id` | `gcn_` + 32 hex characters |
| `principal_id` | the `prn_` principal (CHECKed) |
| `consent_version` | the consent text version; always `c2-link-v2` today |
| `recorded_at`, `recorded_by` | when, and the caller's principal string |
| `revoked_at`, `revoked_by`, `revoke_reason` | `withdrawn` by the human, or `superseded` by a consent to a newer version |

A partial unique index keeps at most one active (unrevoked) row per
principal. Revoked rows stay as history.

The version is a constant in `internal/glovoconsent` and must equal
mctl-glovo's `linkflow.ConsentVersion`. Changing the text there means a new
version here, in the same release pair: until both match, mctl-glovo refuses
to issue a link code.

## Routes

| Route | Caller | Notes |
|---|---|---|
| `GET /api/v1/glovo/link-consent` | the human | own state only |
| `PUT /api/v1/glovo/link-consent` | the human | claims a slot under the cap; body never read; version fixed server-side; 409 `capacity_reached` at the cap |
| `DELETE /api/v1/glovo/link-consent` | the human | frees the slot; idempotent |
| `GET /api/v1/assistants/glovo-consent/v1/principals/{principal_id}` | mctl-glovo only | `active` + version, or `none`; 503 on any read failure |

"The human" means a human acting directly with a resolved principal: a
GitHub, Dex or federated human session, or a local OAuth token minted for
one. Service, agent and CI identities, surfaces, relayed and delegated
requests, Glovo and support audience tokens and the dev caller are refused
with 403 `glovo_consent_human_required`.

The read route is confined in both directions like the basket join: the one
configured federated service identity reaches only that prefix, and nobody
else reaches it. It is rate limited per principal (60 per minute), on top
of the global per-caller limit.

Every record and every withdrawal, refused or not (not a human, principal
unresolved, capacity reached),
writes an audit row: `glovo.link_consent.record` and
`glovo.link_consent.revoke`, with the principal, consent id and version.

## Access requests and the decision page

Self-service access (mctl-glovo#82, stage B). The access side lives in the same
store (`glovo_access_requests`, append-only `glovo_access_events`) and is
mounted only when the store has it.

| Route | Caller | Notes |
|---|---|---|
| `GET/PUT/DELETE /api/v1/glovo/access-request` | the human | own request only: read, open (idempotent while pending, 409 `glovo_access_already_approved`), withdraw |
| `GET /api/v1/admin/glovo/access-requests` | a direct human platform administrator | live pending requests, oldest first, each with its `decide_url` when the page is mounted; a failed or inconsistent read is 503, never an empty list |
| `GET /glovo/access-approvals/{principal_id}` and the `start`, `callback`, `confirm` steps under `/glovo/access-approvals/` | a decider, in a browser | the decision page below |

Approving, rejecting and revoking happen **only** on the decision page. There is
no bearer, token, service or agent route that decides. (The one-time token of a
decide link, below, is not such a route: it narrows a link, and the page still
asks for everything it asks for without one.)

The page is the release approval page's machinery with its own paths, cookie
(`__Host-mctl_glovo_access_decision`) and flow kinds, and it takes the release
page's configuration (the same ZITADEL client, `RELEASE_APPROVAL_DECIDERS`,
`RELEASE_APPROVAL_REQUIRED_AMR`), like the release window page. It is mounted
when that configuration is complete and the access store is wired. The ZITADEL
client's redirect URIs must include `<SELF_URL>/glovo/access-approvals/callback`
before the page can be used.

- Fresh sign-in (`prompt=login`, `max_age=0`, PKCE S256, nonce); the ID token
  must be issued to the page's client and its `amr` must name a required method
  (default `mfa`); the person must be a resolved human admin acting directly and
  one of the deciders. Anyone else gets the same "no such request" answer.
- The decision form carries a one-time challenge and CSRF token bound to the
  browser cookie, kept in the shared flow store (several replicas) and spent
  with an atomic take; a replay, a wrong token or another browser decides
  nothing.
- The access row is read again at confirm and must still be what the page
  showed (status, requested and decided times). Approve and reject apply to a
  live pending request only, revoke to approved access only; an expired pending
  request cannot be approved. The store enforces the same, so a second decider
  gets 409.
- A decider cannot reject their own request (a self-rejection is stored like a
  withdrawal and would read as `none`); approving or revoking one's own access is
  allowed, since the owner is the only decider.
- A reason is mandatory (at most 500 characters, no control characters) and is
  recorded with the decision; the store appends an event with the actor (the
  decider's principal id) and the reason. Approve passes `GLOVO_C2_CAPACITY` to
  the store, which claims the slot when `GLOVO_ACCESS_REQUIRED` is on.
- Every dependency failure (flow store, access read, store write) is a 503 and
  decides nothing; nothing is retried silently.
- The page shows the principal id, status and times only. The signed-in person's
  login name is neither shown, stored nor logged. One audit row
  (`glovo-access-approval-page`) is written per attempt with the principal id and
  outcome.
- Plain server-rendered HTML: no script, no external resource, CSP
  `default-src 'none'`, `frame-ancestors 'none'`, `Cache-Control: no-store`.

Revoking ends the `glovo:c2` grant at the next check, because the grant source
reads the access state live. What happens to a live OAuth grant afterwards: a
tool request made while access is revoked is refused and leaves the grant as it
is; the first refresh made in that window destroys the grant and its token
family, and re-approving access does not revive them, so the person links again.

## Notifications and the decide link (stage C)

Dark unless `GLOVO_ACCESS_NOTIFY_ENABLED=true` (below). With the switch off
nothing in this section happens: no row is written, nothing is sent, and the
decision page behaves as in stage B.

### Outbox

The access store appends one row to `glovo_access_notifications` in the same
transaction as the change it tells, so a notification exists exactly when its
decision does:

| Trigger | Kind | Goes to |
|---|---|---|
| a request is opened | `owner_card` | the owner's Telegram review chat |
| the owner approves | `approved` | the requester's email |
| the owner rejects | `rejected` | the requester's email |
| a pending request passes its seven days | `lapsed` | the requester's email |

A withdrawal by the requester sends nothing. **Revoking sends nothing either**:
the design names a revoke email (5.7) but its Appendix A has no text for one,
and no text is invented here. Lapsing stays derived at read time; a sweep in the
delivery loop appends the `lapsed` row once the expiry has passed.

One row per request and kind (`UNIQUE (principal_id, requested_at, kind)`).

### Delivery

A loop in mctl-api (one round a minute) delivers the rows through the mctl-web
Worker's private bridge `POST /api/internal/glovo-access/notify`, with the same
contract as the signup decision email: lease a row for two minutes, POST it as
the customer-lifecycle machine with a stable `delivery_key`, store the Worker's
receipt. The key is a hash of the principal, the kind and the request time, so
neither the Worker nor the mail provider learns the principal from it.

- Delivery is beside the decision, never part of it. The decision is committed
  before its row can be leased, and the loop's store interface has no call that
  writes an access row. A failed send is retried when the lease runs out, for 23
  hours; after that the row is closed as `expired` and counted.
- A row overtaken by a later change (the request was decided, withdrawn or
  asked again) is closed as `superseded` and not sent late.
- The requester's address is not stored in mctl-api. It is read from the IdP
  for each attempt, through the customer-lifecycle machine: the customer is
  found by the username the identity hook gave them, inside the customers
  organization, held to the same proof a deletion needs (a human of that
  organization with exactly one IdP link, naming the principal's Google subject
  or GitHub id), and must have a verified address. It is passed to the Worker
  with the mail and is neither stored nor logged here.
- A principal with no such customer (staff, an agent, one holding both a Google
  and a GitHub identity, a GitHub customer whose login changed since signup) has
  no recipient: the row is closed as `no_recipient`. Only the IdP's own empty
  listing or an unverified address counts as absence; a refused or malformed
  answer is a failure and is retried. One ambiguity remains: ZITADEL answers a
  search with an empty listing when the machine lacks the permission to see the
  user, which reads as `no_recipient`. Watch that outcome after turning the
  switch on.
- Observability: `mctl_glovo_access_notifications_total{kind,outcome}` (`sent`,
  `superseded`, `no_recipient`, `expired`, and one outcome per failing step) and
  one log line per attempt with the row id, kind and outcome. No address,
  principal id, token or link is logged.

The Worker sends the three fixed texts of the design's Appendix A (English, then
Russian) from `MCTL <noreply@mctl.ai>` with no reply-to, and nothing else: no
field of the request is copied into a mail. The pages served through
glovo.mctl.ai are untouched.

### Owner card

The card is a plain Telegram message to the Worker's review chat (the one the
invitation requests use): the masked identity (`google:a***`), the request and
expiry times, and a link to the decision page. It decides nothing. mctl-api has
no channel to mctl-telegram that can send a message, so the card goes through
the Worker's bot; it is at-least-once like the invitation alert.

### Decide link

The card's link is `<SELF_URL>/glovo/access-approvals/{principal_id}?t=<token>`.

- The token is 32 random bytes. Only its SHA-256 is stored
  (`glovo_access_decide_tokens`), bound to the principal and to the request
  (its `requested_at`), expiring with the request. Because the raw token is
  never stored, it is minted when the card is sent, not when the request is
  opened; a retried card carries a fresh token.
- The page checks the token when it opens and again after the sign-in, and the
  store consumes it in the same transaction as the approval or rejection. A
  replay, an expired token, another principal's token or a token of an earlier
  request decides nothing (410 on the way in, 409 at the decision).
- Every decision and every withdrawal retires all unused tokens of the request.
- The token replaces no check: the fresh sign-in, the second factor and the
  deciders list apply to a link exactly as without one.
- A link that carries a token is held to it. It never falls back to the
  token-less page, and it cannot revoke.
- **Opening the page without a token keeps working** for a decider. That is the
  admin list's `decide_url` and the only way to revoke (approved access has no
  card and no token). The token is what makes a link in a chat single-use; the
  sign-in is what proves the person, with or without it.
- The page that receives the token sets `Referrer-Policy: no-referrer`. The
  token travels on from there as a form field, and only its hash is kept in the
  flow store.

### Turning it on

1. Deploy the mctl-web Worker with the bridge and set its
   `GLOVO_ACCESS_NOTIFY_ENABLED` to `true` (it needs its existing
   `RESEND_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, the
   `ACCESS_REQUESTS` namespace and the lifecycle machine pins).
2. Make sure the decision page is usable (the redirect URI above).
3. Set `GLOVO_ACCESS_NOTIFY_ENABLED=true` in mctl-api. It needs the consent
   routes with the access store, the decision page, the principal store and the
   customer-lifecycle machine (`ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID`,
   `_CLIENT_SECRET`, `_PROJECT_ID`; the site is `CUSTOMER_DELETION_SITE_URL`,
   default `https://mctl.ai`). Anything missing is one boot-log error and
   notifications stay off.

Requests that were already pending when the switch is turned on get no card
(the card is queued when a request is opened); they do get the lapsed email if
they expire afterwards. They stay in the admin list.

## Capacity and the `glovo:c2` grant

There is no grant list and no per-user step. A principal holds `glovo:c2`
while it has an active consent to the current version
(`glovoconsent.ConsentGrants`, the `GrantSource` backed by this table); a
store error is an error, never a grant.

Every active consent holds one slot, and at most `GLOVO_C2_CAPACITY` are
active at once:

- Recording a new consent claims a slot atomically. The claim runs in one
  transaction under a global advisory lock, so the count and the insert
  cannot interleave: two claims for the last slot give exactly one winner.
  Caps reserve at claim.
- At the cap the answer is 409 `capacity_reached`, a fixed code the link
  page can show as a waitlist message; the refusal is audited.
- Re-recording by a principal that already holds a slot is idempotent and
  takes no second slot. A principal holding a slot under an older consent
  version keeps it when it re-consents.
- Withdrawing frees the slot.
- `GLOVO_C2_CAPACITY` unset, `0` or malformed is closed: the routes stay
  mounted (reads and withdrawals work) but no new consent is recorded, and
  the boot log says so at error level.

Production target (owner decision, 2026-11-16): `GLOVO_C2_CAPACITY=10`, a
plain, non-secret value in mctl-gitops `mctl-api.yaml`, set together with
`GLOVO_CONSENT_ENABLED` in the rollout PR after an owner-approved release.
The code default stays closed.

## Configuration (all default off)

| Variable | Meaning |
|---|---|
| `GLOVO_CONSENT_ENABLED` | `true` mounts the routes; anything but `""`, `false`, `true` is a boot-log error and leaves them off |
| `GLOVO_CONSENT_SERVICE_PROVIDER`, `GLOVO_CONSENT_SERVICE_SUBJECT` | the mctl-glovo federated service identity (an `MCTL_OIDC_PROVIDERS` entry of kind service) |
| `GLOVO_C2_CAPACITY` | the slot cap, a positive integer (at most seven digits, no sign or leading zero); unset, `0` or malformed is closed. Not a secret: a plain value is fine |
| `GLOVO_ACCESS_REQUIRED` | Default `false`: slots are active consents, capacity accounting as above. `true` (mctl-glovo#82) makes approved access requests hold the slots (`Record` stops capping consents) AND makes the `glovo:c2` grant source require `access = approved`, read live at every check, in the OAuth personal-grant paths (code, exchange, refresh, consent page) and in the Glovo scope resolver: revoking access ends the next request, a failed access read or an unknown status is a refusal or 503, never a grant. If the store has no access side the personal grants are not wired at all. Existing consent holders keep working because the one-shot backfill approves every active consent when the flag first flips; a consent recorded afterwards needs an approved access. Anything but `""`, `false` or `true` is a boot-log error and consent stays off. The access routes (`/api/v1/glovo/access-request`) and the `access` field of the service read work either way. Enabling it needs the decision page (above) first, or nobody new gets in |
| `GLOVO_ACCESS_NOTIFY_ENABLED` | Default `false`: no owner card, no email, no outbox row, no decide token. `true` turns on everything in "Notifications and the decide link" above, if its dependencies are there; otherwise one boot-log error and it stays off. Anything but `""`, `false` or `true` is a boot-log error and stays off |
| `GLOVO_CONSENT_DB_URL` | the store's database, else `AUDIT_DB_URL` |

## What mctl-glovo needs next

A `linkflow.ConsentSource` client for the read route, replacing
`UnavailableConsent`: authenticate with the service identity, map `active` to
the version, `none` to `ErrNoConsent`, and every other answer (non-200,
malformed body, a `principal_id` other than the one asked for, a timeout) to
`ErrConsentUnavailable`.
