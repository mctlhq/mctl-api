# Federation registry (slice A)

mctl-api#374, slice A. This is the boundary that turns a verified bearer
token into `(provider, issuer, subject)` plus claims, one step *before* the
canonical principal model ([docs/principals.md](principals.md)). It exists so
that adding or replacing an identity provider is a configuration change to
`internal/auth`, not an edit to `auth.Middleware`.

Authorization and tenant resolution are **unaffected**: `User.ID` /
`User.Groups` / `IsAdmin` still decide access, `ADMIN_USERS` and gitops
tenant membership are untouched, and nothing here changes who counts as an
admin or a tenant member. That is mctl-api#377. This registry only relocates
*how a token is verified* behind a named seam.

The audience flag day — flipping `audience_enforcement` to `enforce` for Dex
and deleting the legacy shim — is its own separately approved follow-up
issue (slice D), because it is the only step in this area that can refuse a
production boot. Nothing in this document authorizes that step.

## Why: one middleware, four token types, an unverified peek

Before this change, `auth.Middleware` decided which verifier ran with a
literal `if/else if` chain, keyed on an **unverified** peek at a JWT's `iss`
claim. There was exactly one OIDC verifier (Dex), bound to one issuer, whose
audience check was silently skipped when `DEX_CLIENT_ID` was empty. Adding a
second identity provider meant editing that chain.

## The contract

```go
// Verified is everything a provider may assert. It has no field able to
// express "speaking for someone else": that is the non-impersonation
// invariant of this boundary, enforced by the type, not by review.
type Verified struct {
    Identity Identity // Provider, Issuer, Subject, Display, Kind
    Claims   Claims   // Groups, GitHubID
}

type Provider interface {
    // Name is the registry key AND the external_identities.provider value
    // this provider's Verified.Identity.Provider must equal.
    Name() string
    // Claims decides routing only, from cheap unverified inspection.
    Claims(t tokenShape) bool
    // Verify proves the token and returns the identity it proves.
    Verify(ctx context.Context, raw string) (*Verified, error)
}
```

`tokenShape` is opaque-vs-JWT plus the JWT's **unverified** `iss`, computed
once per request. It is routing information only: a provider's `Claims`
method must never derive identity, kind, groups or trust from it — only
`Verify`, after checking the signature, may do that.

`Registry.Verify(ctx, raw)`:

1. constant-time match against every static-secret provider, in order:
   `MCTL_AGENT_SERVICE_TOKEN`, each surface token
   (`MCTL_SURFACE_TELEGRAM_TOKEN` / `MCTL_SURFACE_PORTAL_TOKEN`),
   `MCTL_USAGE_WRITER_TOKEN`;
2. for a JWT, exact match of the unverified `iss` against an issuer index
   built from every JWT-routed provider's own declared issuer (the local
   OAuth server's `BaseURL`, each configured OIDC provider's `issuer`);
3. otherwise the single registered opaque-token provider (the GitHub PAT
   validator);
4. no provider claims the token → 401 and
   `federation_token_verifications_total{provider="none",result="unclaimed"}`.

There is deliberately **no** "try every provider" fallback. Once a JWT or
opaque candidate is chosen, a verification failure is final: a token whose
unverified `iss` names provider A but is signed by provider B's key is
refused, never re-routed to B.

After a provider answers, the registry enforces the provider contract before
the result is used:

- `Verified.Identity.Provider` must equal the provider's own `Name()` — a
  provider may only mint identities in its own namespace. The one modelled
  exception is the local-OAuth provider, whose declared namespace is
  `github` by design (it mints only for a login the GitHub OAuth callback
  already verified), not derived.
- `Verified.Identity.Subject` must be non-empty unless
  `Identity.GitHubLoginOnly()`.
- `Verified.Identity.Kind` must be one of `auth.KindHuman`, `auth.KindAgent`,
  `auth.KindService`.

A violation is refused with 401, logged, and counted in
`federation_provider_contract_violations_total{provider}` — this metric
should read zero forever; non-zero means a provider returned an identity
outside its namespace.

`*auth.User` is built in exactly one new place, the unexported
`userFromVerified` in `internal/auth/oidc.go`, from the provider's declared
namespace and the identity it proved — never from token claims directly.
This is what keeps `User`'s discriminating fields (`service`, `githubLogin`,
`surface`, `usageWriter`, `actingPrincipal`, `relaySurface`, ...) unforgeable
by a provider: they stay unexported, set only by constructors inside package
`auth`.

## Non-impersonation

`Verified` has no field able to express an acting principal, a relay
surface, or an on-behalf-of subject. A token's `act`, `on_behalf_of` or any
vendor-equivalent claim is simply never read by any provider in this
package. The two existing on-behalf paths are untouched and stay outside
this boundary entirely: the `mctl-agents-approve` `approver` input (gated on
`IsService()`) and the surface relay (`auth.NewRelayedUser`, reachable only
from `internal/api/handlers_surface_identity.go`).

## Registry invariants (refused at boot)

- **Duplicate provider name** among JWT-routed providers (the local-OAuth
  provider and every configured OIDC entry, including the legacy Dex shim).
- **Duplicate normalized issuer** among the same set (trailing `/`
  stripped): two providers claiming one issuer would make routing
  order-dependent.
- **Reserved provider name**: `github`, `service`, `dev`, `agent` may never
  be used by a *configured* `MCTL_OIDC_PROVIDERS` entry. `agent` is reserved
  because mctl-api#376 introduces `auth.ProviderAgent = "agent"` for
  delegated agent identity — a federation provider must never be able to
  mint an `(agent, ...)` identity ahead of that work landing. (The
  local-OAuth provider is the one built-in exception allowed to declare
  `github` — see above.) `dex` is **not** reserved: it is how an operator
  replaces the legacy shim while keeping existing `external_identities`
  rows (`provider='dex'`) resolving.
- **Collision with a registered surface name** (`telegram`, `portal`,
  `internal/surfaceid`): both write into the same
  `external_identities.provider` namespace, so a provider named after a
  surface would collide with identities mirrored from surface links.
- **More than one opaque-token provider**: an opaque token carries nothing
  to route on, so there can be at most one (the GitHub PAT provider).

## Configuration: `MCTL_OIDC_PROVIDERS`

A JSON array, parsed by `auth.ParseOIDCProviders` and validated in
`config.validate` (same style as `OAUTH_PREREGISTERED_CLIENTS`):

```json
[
  {
    "name": "dex",
    "issuer": "https://ops.mctl.ai/api/dex",
    "audiences": ["mctl-api"],
    "audience_enforcement": "audit",
    "subject_claim": "sub",
    "display_claims": ["preferred_username", "email", "sub"],
    "groups_claim": "groups",
    "kind": "human"
  }
]
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `name` | yes | — | The provider's identity namespace; must not repeat, be reserved, or collide with a surface name. |
| `issuer` | yes | — | Matched exactly against the token's `iss`, both for routing and by the underlying verifier. Must not repeat (normalized) across providers. |
| `audiences` | yes | — | Non-empty. The `SkipClientIDCheck` escape hatch is not reachable from this variable — every explicit entry validates an audience. |
| `audience_enforcement` | no | `enforce` | `audit` accepts a mismatched token and counts `federation_audience_mismatch_total{provider}`; `enforce` refuses it. |
| `subject_claim` | no | `sub` | Claim that becomes `Identity.Subject`. |
| `display_claims` | no | `["preferred_username","email","sub"]` | Tried in order for `Identity.Display` — this reproduces the pre-registry Dex fallback as configuration, the concrete meaning of "swappable". |
| `groups_claim` | no | `groups` | Claim read into `Claims.Groups`. |
| `kind` | no | `human` | One of `human`, `agent`, `service`. |

A malformed value, an entry missing `audiences`, an invalid
`audience_enforcement`, a reserved or surface-colliding name, or two entries
sharing a name or a normalized issuer all refuse startup, naming the
offending entry.

### The legacy Dex shim

Unset `MCTL_OIDC_PROVIDERS` (or an array with no entry naming the Dex
issuer) reproduces today's single-Dex configuration exactly, synthesized
from `DEX_ISSUER_URL` / `DEX_CLIENT_ID`:

- `DEX_CLIENT_ID` set → `audiences: [DEX_CLIENT_ID]`, `audience_enforcement:
  enforce` (library-equivalent to the pre-registry `ClientID` check).
- `DEX_CLIENT_ID` empty → no audience decision is computed at all;
  `federation_audience_check_skipped_total{provider="dex"}` is incremented
  on every verification, and a startup warning names the variable to set.

If an explicit `MCTL_OIDC_PROVIDERS` entry claims the same (normalized)
issuer as `DEX_ISSUER_URL`, the shim is **not** synthesized — the explicit
entry supersedes it. Boot logs which of the two is active. Two registrations
on one issuer would otherwise be a boot refusal, so this is how an operator
replaces the shim: change the entry's `issuer` / `audiences` and keep
`name: "dex"` (existing `external_identities` rows with `provider='dex'`
keep resolving), or add a second entry under a new name and migrate users by
linking.

An unreachable OIDC issuer at boot — for either the shim or an explicit
entry — is **not** one of the conditions that refuses startup. It is logged
and that one provider is simply omitted, the same graceful degradation Dex
init failure has always had.

## `MCTL_FEDERATION_DISABLED`: the kill switch

Same shape as `PRINCIPALS_DISABLED`: any value except an explicit
`false`/`f`/`0`/`no`/`off` (or empty) restores the pre-registry `if/else if`
chain in `auth.Middleware`, unchanged — including its plain (non-constant-
time) service-token compare, which is the one thing this proposal otherwise
fixes (see below). The old chain stays in the tree, exercised by its own
tests, until slice D deletes it.

## The one behaviour fix: constant-time static-secret matching

Before this change, `staticServiceUser` compared `MCTL_AGENT_SERVICE_TOKEN`
with a plain `==`, while the surface and usage-writer checks already used
`crypto/subtle.ConstantTimeCompare`. All three now route through one helper:

```go
func secretMatches(configured, presented string) bool {
    if configured == "" {
        return false
    }
    return subtle.ConstantTimeCompare([]byte(configured), []byte(presented)) == 1
}
```

An empty configured secret never matches, and no comparison against the
presented token is even performed in that case. This is a **deliberate,
stated behaviour fix** — the accept/reject outcome is identical for every
input; only the timing signal is removed. It is pinned two ways: a
behavioural table test over `secretMatches`, and a source-scanning test
(`internal/auth/provider_static_test.go`) asserting the new static-secret
path (`provider_static.go`) contains no `==`/`!=` comparison against a
presented token and does reference `subtle.ConstantTimeCompare`.
`oidc.go`'s original `staticServiceUser` keeps its plain `==` deliberately:
it is the pre-registry fallback `MCTL_FEDERATION_DISABLED` restores
wholesale, and is not part of that pin.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `federation_token_verifications_total` | `provider`, `result` (`ok`\|`invalid`\|`unclaimed`) | Every verification attempt through the registry. |
| `federation_verify_duration_seconds` | `provider` | Time spent verifying, per provider. |
| `federation_audience_check_skipped_total` | `provider` | No audience decision was even computed (the legacy shim with an empty `DEX_CLIENT_ID`). |
| `federation_audience_mismatch_total` | `provider` | A decision *was* computed, came out negative, and the token was accepted anyway (`audience_enforcement: audit`) — the canary gate. |
| `federation_provider_contract_violations_total` | `provider` | A provider returned an identity outside its own namespace. Should be permanently zero. |

The two audience counters are deliberately distinct: "we never checked" and
"we checked, it failed, we let it through" are different operational facts,
and only the second can gate a flag day.

## Cut-over order

1. **Slice A (this document).** Registry, behaviour-identical plus the one
   stated constant-time fix. Rollback: `MCTL_FEDERATION_DISABLED=true`.
2. **Production canary, audit mode.** Set `MCTL_OIDC_PROVIDERS` to an
   explicit Dex entry with real `audiences` and `"audience_enforcement":
   "audit"`. Gate for at least 7 days on
   `federation_audience_mismatch_total{provider="dex"} == 0` and
   `federation_token_verifications_total{provider="dex",result="ok"}`
   holding its pre-change rate. Rollback: unset `MCTL_OIDC_PROVIDERS`; the
   shim returns.
3. **Slice D (separate, separately approved issue).** Flip
   `audience_enforcement` to `enforce`, then delete the legacy shim, the
   `SkipClientIDCheck` branch, the retained pre-registry chain and
   `MCTL_FEDERATION_DISABLED`. The only step that can refuse a production
   boot.

Not covered by this document (explicitly out of scope for slice A, see
mctl-api#374's requirements/design records):

- Carrying the numeric GitHub id into local OAuth JWTs (slice B).
- Re-resolving groups on refresh (slice C).
- Any change to authorization, `ADMIN_USERS`, or tenant resolution by GitHub
  login — that is mctl-api#377.
