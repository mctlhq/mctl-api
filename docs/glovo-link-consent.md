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
| `GLOVO_CONSENT_DB_URL` | the store's database, else `AUDIT_DB_URL` |

## What mctl-glovo needs next

A `linkflow.ConsentSource` client for the read route, replacing
`UnavailableConsent`: authenticate with the service identity, map `active` to
the version, `none` to `ErrNoConsent`, and every other answer (non-200,
malformed body, a `principal_id` other than the one asked for, a timeout) to
`ErrConsentUnavailable`.
