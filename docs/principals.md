# Canonical principals (phase 1)

mctl-api#373. Decision record: the owner-approved comments on that issue
(D1–D3, 2026-09-23, and the phase-1 decisions, 2026-09-24).

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
  `principal_resolution_failed_total`. Phase 2 fails closed instead.

## Surface identity links: mirrored, not replaced

`surface_identity_links` stays the source of truth for challenge → redeem
and for a link's expiry. A redeemed link is written to
`external_identities` (`provider=<surface>`) for the linked human in the same
transaction; a revoked link sets `revoked_at` there. A failed mirror rolls
the redeem back. That is why both live in one database
(`SURFACE_IDENTITY_DB_URL`, else `AUDIT_DB_URL`). A surface may not be named
after an authentication provider (`github`, `dex`, `service`, `dev`): its
mirror rows would collide with real identities.

## Backfill

Runs automatically after the first successful gitops sync, on every start,
and is idempotent. Source: gitops tenant and team members. For each login
without a live GitHub identity it looks up the numeric id and provisions a
human principal, then mirrors every live surface link whose human is now
known. `audit_events.user_id` is never a source: it carries no provider, so
a Dex username there is indistinguishable from a GitHub login.

## Not in phase 1

Authorization and tenant membership still use `User.ID` and `User.Groups`.
Records do not store principal ids yet (dual-write is the next step).
