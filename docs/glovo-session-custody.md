# Glovo session custody (mctl-api#1006)

Decision record and contract for holding the owner's own Glovo consumer
session inside the mctl platform. Code: `internal/glovoprovider/session`,
loader: `cmd/glovo-session-load`. Nothing here is wired into a route, an MCP
tool or startup; `Config.Enabled` is false by default.

Scope. The owner cancelled the "MCTL holds no Glovo credentials" rule for his
own account on 2026-11-11 (mctl-api#1006, comment 6782512154). This record
covers custody of that one session. It does not extend the exception to any
other user, and it does not touch the Terms-of-Use, market or liability
questions (O1 to O4 of the audit); those stay open.

## The problem in one paragraph

The upstream login yields an access token and a **rotating** refresh token: a
refresh returns a new pair, and the old refresh token stops working. So
custody is a write-heavy problem, not a secret-file problem. Every refresh must
(a) happen once, never in parallel across the two mctl-api replicas, and (b)
persist the new refresh token, or the session is dead. Upstream stores one
plaintext JSON file per machine, which has neither property across replicas
(and recurses without bound on a persistent 401/403, api.mjs:293-297).

## Decision

**Postgres row, AES-256-GCM sealed, key by reference; refresh serialized by a
row lease and committed by compare-and-swap.**

- Table `glovo.glovo_provider_sessions`, one row per provider connection id,
  holding `ciphertext` (`nonce || AES-256-GCM`), `key_id`, `generation`,
  `state`, a refresh `lease`, a `refresh_intent` flag and non-secret metadata.
- The data key is a 32-byte key from a keyring (`key_id` to key). It is read
  only from two **named** environment variables (`GLOVO_SESSION_KEK_ID`,
  `GLOVO_SESSION_KEKS`), which production fills from an ExternalSecret that
  reads Vault. The database never sees it, so a dump, a backup (barman to R2)
  or a SQL console shows ciphertext only.
- The AES-GCM additional data is `tenant | principal | connection | generation
  | key_id`. A blob copied to another row, another owner or an older
  generation does not authenticate (`ErrCorrupt`). Tested per component.
- Key rotation: add the new id to `GLOVO_SESSION_KEKS`, switch the active id,
  and each refresh re-seals its row under the active key; drop the old id once
  no row carries it (`SELECT key_id, count(*) ... GROUP BY 1`).

## Options considered

| Option | Verdict | Why |
| --- | --- | --- |
| Vault KV v2 as the store, read through an ExternalSecret | Rejected | ExternalSecret is a one-way sync, Vault to Secret, on a refresh interval. A rotated token written by a pod has no path back, and a read-through copy is stale by design. The refresh token would also live in a Kubernetes Secret, readable by anything with `get secret` in the namespace. |
| Vault KV v2 as the store, written by mctl-api (with `cas`) | Rejected for now | Vault KV has check-and-set, so the primitives exist. But mctl-api's Vault client is a read-only KV reader and its policy is read-only; granting the runtime role write on a path that also holds secrets is a larger blast radius than one encrypted row. There is no lease primitive either (a second mechanism is needed), each refresh is a Vault write plus a Postgres write with no shared transaction, and the connection lifecycle (end connection, revoke, audit) already lives in Postgres. Revisit if Vault gets a dedicated write-only `glovo-session/*` policy and a Vault-managed transit key; see open question 3. |
| Plain Postgres column | Rejected | A backup, a replica, a `pg_dump` for debugging or a leaked read-only DSN would hand over a live account session. Encryption with an external key makes the database alone insufficient. |
| Postgres `pgcrypto` with the key in the query | Rejected | The key travels in SQL text and lands in `pg_stat_statements`, server logs and slow-query logs. Encrypting in the application keeps key and plaintext out of the database process. |
| Sealed file on a PVC, or the upstream `session.json` mounted | Rejected | Two replicas would each hold a copy, each refreshing and rotating the other's token away. A single replica pinned to one volume is a new single point of failure and a backup problem. |
| Cloud KMS / Vault transit for the data key | Deferred | Strictly better key custody (no key in process memory at rest, audit of each unwrap). Not available in this cluster today; the `Keyring` seam (`key_id`) is where it plugs in. |
| Local device connector (audit option B) | Out of scope | The owner chose custody inside mctl for his own account. Still the better design for any other user. |

Residual risk, stated plainly: anyone who can read the table AND the key, or
who compromises a running mctl-api process, gets live tokens. Encryption
removes the "dump leaks the session" class, not the "process compromised"
class. Mitigations are the kill switch below, the narrow DB role (no DELETE,
no access from other services) and the fact that tokens are decrypted only in
the refresh and serve path.

## Concurrency: one refresh, never two, never a lost rotation

Per connection, at most one `/oauth/refresh` request is in flight across all
replicas.

1. **One flight per connection, one lease holder per flight.** The only two
   entry points that can refresh, `AccessToken` and `Rejected`, both go
   through one process-local single-flight keyed by the connection alone;
   the seen/force logic runs inside the flight. The lease holder id is
   `HolderID/<random>` per flight, not per process, because the lease is
   re-entrant for one holder: a process-wide id would let a second flight
   (or a pod that shares a `HolderID`) take the lease and send the same
   rotating refresh token again (found in review of #1020). The two layers
   are independent: either alone serializes the flights, and the tests kill
   each layer's removal separately only where the other cannot mask it
   (holder alone: two managers with one `HolderID`; both removed:
   `AccessToken` plus `Rejected` race).
2. **Row lease.** `AcquireLease` is one `UPDATE ... WHERE lease_holder IS NULL
   OR lease_holder = me OR lease_until <= clock_timestamp()`. Time is the
   database clock, so replica clock skew does not matter. A replica that
   finds the lease held waits (bounded, `WaitMax`) and then reads the
   result instead of refreshing.
3. **Double-check under the lease.** After acquiring, the replica compares
   the generation it saw with the row's. If another replica committed in
   between, it uses that token and does not call the provider.
4. **Compare-and-swap commit.** `Commit` is one `UPDATE ... WHERE generation
   = expected AND lease_holder = me AND state = 'active'`, bumping the
   generation and clearing the lease and the intent. An owner load (`Put`),
   a revoke or a relogin marker changes the generation or the state, so an
   in-flight refresh of an older lineage fails with `ErrStale` and cannot
   overwrite a newer session or resurrect a revoked one. Three independent
   guards (CAS, lease, state) plus a table CHECK (`ciphertext IS NOT NULL`
   exactly when `state = 'active'`).
5. **Bounded retry on 401/403.** `Rejected(key, generation)` allows one forced
   refresh per generation. A newer generation is simply returned. A token that
   came from a refresh and is rejected again makes the session
   `relogin_required`. This replaces upstream's unbounded recursion.

## Crash between the provider response and the persist

The new refresh token exists in exactly one place, the memory of the process
that got the response, until `Commit` succeeds. What the design does, in order:

1. **Persist on a context that is not the caller's** (`WithoutCancel` plus its
   own timeout) with bounded retries (`PersistAttempts`, default 5), so a
   cancelled request or a transient database error does not drop the token.
   Tested: two failed commits then success; caller cancelled the instant the
   provider answers.
2. **The lease TTL (45 s) exceeds** the refresh timeout (10 s) plus the persist
   window, so a live holder is not taken over.
3. **An intent flag** is set when the lease is taken and cleared only by a
   commit or by a definitive outcome (provider rejection, request provably
   not sent). A timeout, a reset, a 5xx or a malformed body leaves it set:
   the provider may have rotated the token.
4. **If the process really dies** between response and persist, the new token
   is gone. That cannot be made impossible from the client side: the rotation
   happens at the provider before we hold the new token, so there is no
   write-ahead point. The recovery is explicit and bounded. When the lease
   expires, the next replica sees the set intent and tries the stored (old)
   refresh token once:
   - if the provider still accepts it (a grace window; **unverified for
     Glovo**), the pair is committed and service resumes (`recovered` test);
   - if the provider rejects it, the session becomes `relogin_required` with
     reason `refresh_outcome_unknown_then_rejected`, the tokens are wiped,
     and every later call returns `ErrReloginRequired` without touching the
     provider (`explicit relogin_required` test, including that a reload by
     the owner restores service).
   No partial state exists at any step: the row is either the old generation
   with the intent set, or the new generation, or `relogin_required`.

Expected frequency: a process kill inside a window of tens of milliseconds
once per access-token lifetime (the upstream token life is not known; the
audit says unverified). The cost when it happens is one owner re-login.

## Binding, revocation, expiry, audit

- **Binding.** The key is `(tenant, principal, connection)`. Every statement
  filters on all three; a mismatch reads as `ErrNotFound`, so existence is
  not leaked across owners. `Put` refuses a connection id that belongs to
  another owner. The wiring slice must call `Load` only for a connection that
  is live for the same tenant and principal in `glovo.glovo_connections`, and
  must call `Revoke` whenever a connection ends (this package has no foreign
  key on purpose, so it can ship unwired).
- **Kill switches.** (1) `Config.Enabled` false by default; (2) `Config.Kill`
  is read on every call and returns `ErrDisabled` before the store or the
  provider is touched; (3) `Revoke(key)` wipes the ciphertext and sets
  `revoked`, effective immediately for every replica because state is read
  from the row; an in-flight refresh cannot write back. Only an explicit
  owner load re-enables a revoked row.
- **Expiry and re-login.** `AccessToken` never returns an empty token with a
  nil error. A session that needs the owner is `*ReloginError`
  (`errors.Is(err, ErrReloginRequired)`) with a stable reason code
  (`refresh_rejected`, `access_rejected_after_refresh`,
  `refresh_outcome_unknown_then_rejected`, `expired_without_refresh_token`),
  or `ErrRevoked`. `Status` returns the state and reason as data for the
  connection UI. A provider outage is `ErrUnavailable` and leaves the session
  active; it is never turned into `relogin_required` and never into empty
  data. This follows the repo rule that "could not observe" is not "absent".
- **Audit.** `Auditor.Record(Event)` receives kind, tenant, principal id,
  connection id, generation and a code. No token, no provider text, no
  profile data. `Secret` redacts under `%v`, `%+v`, `%#v`, `%s` and JSON.
  Error texts name the operation only. The upstream profile fields (name,
  email, coordinates, device ids) are dropped by the parser and never stored.
  Tested by scanning errors, audit events and formatted records for the
  synthetic token prefix, including a provider error that echoes a token.

## Owner load (one time, run by the owner, never by an agent)

The loader reads the upstream session JSON from **stdin only**, keeps the two
tokens and the expiry, seals, writes, and prints a secret-free status. It never
calls Glovo and refuses to run without `--confirm-own-account`.

One-time key creation (the key is never printed):

```sh
printf 'k1=%s' "$(openssl rand -base64 32)" \
  | vault kv put secret/platform/mctl-api/glovo-session GLOVO_SESSION_KEKS=- GLOVO_SESSION_KEK_ID=k1
```

Load (from a checkout of this branch, with the database reachable, for example
through `kubectl port-forward` to shared-pg using the glovo runtime role):

```sh
export GLOVO_SESSION_DB_URL='<postgres URL of the glovo database, runtime role>'
export GLOVO_SESSION_KEK_ID=k1
export GLOVO_SESSION_KEKS="$(vault kv get -field=GLOVO_SESSION_KEKS secret/platform/mctl-api/glovo-session)"
go run ./cmd/glovo-session-load \
  --tenant '<tenant id>' --principal '<prn_...>' --connection '<gcn_... of the active connection>' \
  --confirm-own-account < ~/.glovo/session.json
```

Afterwards: `unset GLOVO_SESSION_KEKS GLOVO_SESSION_DB_URL`. After a successful
load the local `~/.glovo/session.json` is **no longer a valid copy**: the first
refresh in mctl rotates the refresh token and invalidates the one in the file,
and the reverse holds too (a refresh by the local Glovo MCP kills the stored
one). The owner must pick one holder of the session at a time, or log in again
for the second.

## What this slice does not do

No live adapter or HTTP call to Glovo (the `Refresher` is an interface; the
adapter must map a definitive 400/401/403 to `ErrRefreshRejected`, a
pre-connect failure to `ErrRefreshNotSent`, and must not retry inside one
call). No route, MCP tool, config key, chart value or startup wiring. No
migration in the migration chain: `session.ApplySchema` exists and is tested
but is not called by `glovo.ApplySchema` yet. Not a release, not a deploy.

## Open questions for the owner

1. Is Postgres (encrypted row) accepted as the store of the live session, with
   the key in Vault and delivered through an ExternalSecret?
2. The Vault path and the ExternalSecret name for `GLOVO_SESSION_KEKS`
   (proposed `secret/platform/mctl-api/glovo-session`): approve, or name another.
3. Is a Vault-managed key (transit) available or planned? That would replace
   the env keyring.
4. Token lifetime and refresh-grace behavior of Glovo are unverified (audit
   O3). The crash recovery above is correct either way, but it only avoids a
   re-login if Glovo tolerates one reuse of the old refresh token.
5. The session must live in exactly one place: mctl or the local Glovo MCP,
   not both. Which one after the load?
