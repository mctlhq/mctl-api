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
   `MCTL_USAGE_WRITER_TOKEN`, `MCTL_EVIDENCE_WRITER_TOKEN`,
   `MCTL_REGISTRY_PUBLISHER_TOKEN`;
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
- **Reserved provider name**: `github`, `service`, `dev`, `agent`,
  `github-actions` may never
  be used by a *configured* `MCTL_OIDC_PROVIDERS` entry. `agent` is reserved
  because mctl-api#376 introduces `auth.ProviderAgent = "agent"` for
  delegated agent identity — a federation provider must never be able to
  mint an `(agent, ...)` identity ahead of that work landing. (The
  local-OAuth provider is the one built-in exception allowed to declare
  `github` — see above — and the GitHub Actions provider the one allowed to
  declare `github-actions`, see "GitHub Actions" below.) `dex` is **not**
  reserved: it is how an operator
  replaces the legacy shim while keeping existing `external_identities`
  rows (`provider='dex'`) resolving.
- **Collision with a registered surface name** (`telegram`, `portal`,
  `internal/surfaceid`): both write into the same
  `external_identities.provider` namespace, so a provider named after a
  surface would collide with identities mirrored from surface links.
- **More than one opaque-token provider**: an opaque token carries nothing
  to route on, so there can be at most one (the GitHub PAT provider).
- **`grant_groups` on the trusted Dex slot** (an entry named `dex` on
  `DEX_ISSUER_URL`), whether `true` or `false`: that slot always passes its
  groups unfiltered, so the field would be silently ignored there.

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
| `groups_claim` | no | `groups` | Claim read for groups: an array of strings, or (outside the trusted Dex slot) an object whose keys are the group names (ZITADEL's `urn:zitadel:iam:org:project:roles`). Any other shape, or non-string array elements, counts in `federation_groups_claim_unreadable_total{provider}` and is dropped. It reaches `User.Groups` only for the trusted Dex slot or when `grant_groups` is on (see "Groups" below). |
| `kind` | no | `human` | One of `human`, `agent`, `service`. |
| `grant_groups` | no | `false` | Whether this entry's groups reach `User.Groups`, i.e. grant tenant access. Off: the claim is dropped and counted in `federation_groups_withheld_total{provider}`. On: kept, with `admins` still stripped. Refused at boot on the trusted Dex slot. See "Groups" below. |

A malformed value, an entry missing `audiences`, an invalid
`audience_enforcement` or `kind`, a reserved or surface-colliding name, or two
entries sharing a name or a normalized issuer all refuse startup, naming the
offending entry — unless `MCTL_FEDERATION_DISABLED` is on (below).

### The legacy Dex shim

Unset `MCTL_OIDC_PROVIDERS` (or an array with no entry named `dex`)
reproduces today's single-Dex configuration exactly, synthesized from
`DEX_ISSUER_URL` / `DEX_CLIENT_ID`:

- `DEX_CLIENT_ID` set → `audiences: [DEX_CLIENT_ID]`, `audience_enforcement:
  enforce` (library-equivalent to the pre-registry `ClientID` check).
- `DEX_CLIENT_ID` empty → no audience decision is computed at all;
  `federation_audience_check_skipped_total{provider="dex"}` is incremented
  on every verification, and a startup warning names the variable to set.

If an explicit `MCTL_OIDC_PROVIDERS` entry is **named `dex`**, the shim is
**not** synthesized — the explicit entry supersedes it, whatever its issuer.
Boot logs which of the two is active. The name is the identity namespace, so
this is how an operator replaces the shim: keep `name: "dex"` and change the
entry's `issuer` / `audiences` (existing `external_identities` rows with
`provider='dex'` keep resolving), or add a second entry under a new name and
migrate users by linking. An entry under any other name on the Dex issuer
does not replace the shim: both would claim one issuer, and boot is refused
with a duplicate-issuer error naming both.

Which of these keeps the `admins` group is a separate, narrower rule. A
`dex` entry on the **same** issuer as `DEX_ISSUER_URL` (the audit canary
below) keeps Dex's unfiltered groups exactly as the shim does, because the
operator already trusts that issuer. A `dex` entry repointed at **any other**
issuer is a new trust decision: like every other `MCTL_OIDC_PROVIDERS` entry,
its groups are withheld unless it sets `grant_groups: true`, and even then
`admins` is stripped (see "Groups" below).

An unreachable OIDC issuer at boot — for either the shim or an explicit
entry — is **not** one of the conditions that refuses startup. It is logged
and that one provider is simply omitted, the same graceful degradation Dex
init failure has always had.

### Groups

`User.Groups` is still the authorization input: `IsAdmin` reads `admins`
from it and `HasTenantAccess` reads tenant names from it. A groups claim from
a newly federated identity provider would therefore grant tenant access the
moment a group is named like a tenant. Until mctl-api#377 moves
authorization onto principals, every `MCTL_OIDC_PROVIDERS` entry other than
the trusted Dex slot is fail-closed:

| Provider | Groups reaching `User.Groups` |
|---|---|
| Legacy shim, or `dex` on `DEX_ISSUER_URL` | The claim, unfiltered (`admins` included) — unchanged from before the registry. |
| Any other entry, `grant_groups` unset or `false` | None. A non-empty claim is counted in `federation_groups_withheld_total{provider}`. |
| Any other entry, `grant_groups: true` | The claim with `admins` stripped. |

The identity itself is unaffected: the caller is still authenticated, keyed
on `(provider, issuer, sub)` in `external_identities`, and resolved to a
principal. It simply holds no tenant and no admin access through this path.

## ZITADEL (mctl-api#434)

ZITADEL is the MCTL human identity provider (mctlhq/.github#157). It enters
here as one more `MCTL_OIDC_PROVIDERS` entry, not as a broker in front of
every request: service tokens, local MCP OAuth JWTs and GitHub PATs are still
verified by mctl-api itself, and the Dex shim keeps running next to it. No
new verifier code: the entry is configuration.

```json
[
  {
    "name": "zitadel",
    "issuer": "https://auth.mctl.ai",
    "audiences": ["<client id of the mctl-api application in ZITADEL>"]
  }
]
```

- **Audience is enforced from day one.** `audience_enforcement` is left at
  its `enforce` default and must not be set to `audit` for this entry: the
  audit mode exists only to canary the *existing* Dex traffic, and there is
  no existing ZITADEL traffic to protect. A token ZITADEL signed for another
  application (or carrying only the project id) is refused with 401 and
  counted in `federation_audience_rejected_total{provider="zitadel"}`.
  ZITADEL puts the project id and the client ids of the project's
  applications in `aud`; only the configured client id is accepted.
- **Tokens must be JWTs.** ZITADEL issues opaque access tokens unless the
  application's token type is set to JWT; an opaque token is routed to the
  GitHub PAT provider and fails there. ID tokens are always JWTs.
- **Identity.** `external_identities` rows are keyed on
  `('zitadel', 'https://auth.mctl.ai', <ZITADEL user id>)`. `User.ID` is
  `preferred_username` (the ZITADEL login name), falling back to `email`,
  then `sub`. It never reads as a GitHub-proven login, so `ADMIN_USERS` and
  GitHub-login tenant resolution never apply to it.
- **No authorization from ZITADEL.** `grant_groups` stays unset: neither a
  `groups` claim nor ZITADEL project roles
  (`urn:zitadel:iam:org:project:roles`) grant tenant or admin access until
  mctl-api#377.
- **Name and issuer are permanent.** `zitadel` is the
  `external_identities.provider` value; renaming the entry, or changing the
  issuer (for example a custom domain), orphans every linked identity.

Rollout is a production canary (mctl-api has no staging): add the entry,
then watch `federation_token_verifications_total{provider="zitadel"}` by
`result` and `federation_audience_rejected_total{provider="zitadel"}` —
a non-zero rejection rate means a client is requesting tokens for the wrong
application. Dex traffic (`provider="dex"`) must be unchanged. Rollback is one
env change: remove the entry from `MCTL_OIDC_PROVIDERS` (or unset the
variable if it is the only one). ZITADEL tokens are then unclaimed (401) and
nothing else changes. If `auth.mctl.ai` is unreachable at boot, the entry is
logged and omitted; mctl-api still starts.

## GitHub Actions: CI deploys (mctl-api#530)

A tenant's CI deploys with the job's own GitHub Actions OIDC token instead of
a personal access token. The token proves which repository, event and ref the
job ran for and expires within minutes. The principal it yields can do
exactly one thing: deploy a new tag of the component registered to that
repository.

### Configuration: `MCTL_GITHUB_ACTIONS_OIDC`

Off unless set. When it is unset, a GitHub Actions token is unclaimed (401).

```json
{
  "audience": "https://api.mctl.ai",
  "repository_owners": ["mctlhq"],
  "repository_owner_ids": ["123456"],
  "branches": ["refs/heads/main"]
}
```

| Field | Required | Meaning |
|---|---|---|
| `repository_owners` | yes, non-empty | GitHub owners (org or user logins) whose repositories may deploy. Case-insensitive. |
| `audience` | no, default `https://api.mctl.ai` | The token's `aud` must contain it. Always enforced; there is no audit mode. |
| `repository_owner_ids` | no | When set, `repository_owner_id` must also be one of these immutable ids. |
| `branches` | no, default `["refs/heads/main"]` | Full branch refs a token may come from. Tags (`refs/tags/*`) are always accepted. No wildcards. |

These all refuse startup: a malformed value, `null`, an unknown field, a
missing or empty `repository_owners`, or a branch that is not a full
`refs/heads/...` ref. The exception is while `MCTL_FEDERATION_DISABLED` is on.

The issuer is fixed: `https://token.actions.githubusercontent.com`, with its
JWKS read through OIDC discovery. If discovery fails at boot, the provider is
left out and logged, the same as an unreachable `MCTL_OIDC_PROVIDERS` entry.

### Token policy

The policy runs after the signature, expiry and audience checks. Every rule
fails closed; a missing or non-string claim is a refusal.

- `repository`, `repository_id`, `repository_owner`, `repository_owner_id`,
  `event_name`, `ref` and `ref_type` must all be present. The ids must be
  numeric, and `repository` must be `<repository_owner>/<name>`.
- `repository_owner` must be in `repository_owners`, and its id must be in
  `repository_owner_ids` when that is set.
- `event_name` must be `push`, `workflow_dispatch` or `release`.
  `pull_request` and `pull_request_target` are refused because they run fork
  and unmerged code. Every other event is refused too: `schedule`,
  `workflow_run`, `issue_comment` and the rest can be steered by people
  without write access.
- `ref` must be a tag (`ref_type: tag`, `refs/tags/<something>`) or one of
  `branches` (`ref_type: branch`).

Each refusal logs `github actions token refused` with a `reason` (`issuer`,
`audience`, `claims`, `owner`, `owner_id`, `event`, `ref`). It counts as
`federation_token_verifications_total{provider="github-actions",result="invalid"}`.

### The principal

| Field | Value |
|---|---|
| Identity | provider `github-actions`, issuer as above, subject = `repository_id` (immutable), kind `service` |
| `User.ID` / display | `ci:<owner>/<repo>`; this is what the audit log records |
| Groups | none: no tenant membership and no admin, whatever the token carries |

### What it may call

- **Route gate** (`ciPrincipalGate`). Every route except
  `POST /api/v1/operations/deploy-service/execute` answers
  `403 ci_route_not_allowed`. That includes `/mcp`, every read and every
  other operation. An encoded path is refused.
- **Request policy** (`authorizeCIDeploy`, on the raw request before
  defaults). This replaces the tenant role check for this principal only.
  Every refusal is a `403 ci_deploy_denied` (or 503, see below) and an audit
  entry with `status=denied`.
  - `action` must be `deploy`. `onboard` and `update-config` are refused.
  - Parameters are limited to `action`, `team_name`, `component_name`,
    `dockerfile_repo`, `git_tag` and `dockerfile_path`. Any other parameter
    is refused: env vars, secrets, `clear_*`, host, port, scaling, database,
    template, `image_tag`.
  - `dockerfile_repo` must equal the token's `repository`.
  - The component's `github.com/source-repo` annotation must equal it too.
    The annotation lives in
    `platform-gitops/services/<team>/<component>/catalog-info.yaml` and is
    written by the `onboard` action, which only a tenant developer can run.
    That annotation is the registration.
  - All comparisons are case-insensitive.
  - The component missing, its file missing, or the annotation missing gives
    403.
  - A checkout that cannot be read, a symlink or non-regular entry on the
    path, or a file that does not parse gives 503. "Could not read" is
    neither "not registered" nor "matches".

### Residual risk: repository names are mutable

mctl-api stores no repository ids, and the registration records the
repository by name. Two things contain what that allows:

1. **The owner allowlist.** Under an org owner, only org members can create a
   repository with a freed name.
2. **`repository_owner_ids`.** This covers the owner account itself being
   renamed or deleted and its login re-registered.

Every deploy is attributed to the immutable `repository_id`, so a recreated
repository shows up as a new principal.

### CI usage

```yaml
deploy:
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  runs-on: ubuntu-latest
  permissions:
    contents: write   # push the tag
    id-token: write   # mint the OIDC token
  steps:
    # ... compute and push TAG as before ...
    - name: Trigger mctl deploy-service
      run: |
        set -euo pipefail
        TOKEN=$(curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
          "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://api.mctl.ai" | jq -r .value)
        curl -fsS -X POST https://api.mctl.ai/api/v1/operations/deploy-service/execute \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"action\":\"deploy\",\"team_name\":\"<team>\",\"component_name\":\"<service>\",\"dockerfile_repo\":\"${GITHUB_REPOSITORY}\",\"git_tag\":\"${TAG}\"}"
```

No repository secret is needed. The body must stay flat (no nested
`parameters` object) and must not carry any field outside the allowlist.

## `MCTL_FEDERATION_DISABLED`: the kill switch

Same shape as `PRINCIPALS_DISABLED`: any value except an explicit
`false`/`f`/`0`/`no`/`off` (or empty) restores the pre-registry `if/else if`
chain in `auth.Middleware`, unchanged — including its plain (non-constant-
time) service-token compare, which is the one thing this proposal otherwise
fixes (see below). The old chain stays in the tree, exercised by its own
tests, until slice D deletes it.

While the switch is on, `MCTL_OIDC_PROVIDERS` is neither validated nor built
into a registry, so none of the boot refusals above apply. That is what makes
it a rollback for them too: a value that crash-loops the pod (say, an entry
under a new name on the Dex issuer) is recovered by setting the switch alone,
without first editing the provider JSON. The value is validated again the
moment the switch is turned off.

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
| `federation_audience_rejected_total` | `provider` | A decision was computed, came out negative, and the token was refused (`audience_enforcement: enforce`). Also counted as `result="invalid"` above; this is the audience-only share of it. |
| `federation_provider_contract_violations_total` | `provider` | A provider returned an identity outside its own namespace. Should be permanently zero. |
| `federation_groups_withheld_total` | `provider` | A verified token carried a non-empty groups claim that was dropped because the entry does not set `grant_groups`. What the entry *would* have granted. |
| `federation_groups_claim_unreadable_total` | `provider` | A groups claim could not be fully read (wrong shape, non-string elements, or an object on the trusted Dex slot). Usually a misconfigured `groups_claim`. |
| `github_token_verifications_total` | `kind` (`fine_grained_pat`\|`classic_pat`\|`oauth_app`\|`app_user`\|`app_installation`\|`other`), `result` (`ok`\|`invalid`\|`unavailable`) | Opaque bearer tokens verified by the GitHub provider (mctl-api#525). `kind` is read from GitHub's documented token prefix only. `invalid` means GitHub refused the token (401, or a 403 that is not a rate limit); `unavailable` means the lookup failed (rate limit, timeout, 5xx). The provider is the registry's only opaque fallback, so every non-JWT token no static provider claims lands here: `kind="other", result="invalid"` is mostly not GitHub traffic. Each `ok` also logs `github token verified` with `login`, `kind` and `user_agent`, at most one line per user agent per (login, kind) per hour and at most 4 per window. Not counted on the `MCTL_FEDERATION_DISABLED` path, so the series reads zero there while raw tokens are still accepted. |

`provider` is the provider's namespace, with one exception: mctl-issued
OAuth JWTs (the local-OAuth provider, namespace `github`) are counted as
`provider="mctl_oauth"`, so `provider="github", result="ok"` counts only
raw GitHub tokens accepted as bearers. That series reaching zero is the
gate for retiring `provider_github.go`; `result="invalid"` under `github`
never will, because the GitHub provider is the catch-all for every
unrecognised non-JWT bearer. The name `mctl_oauth` is reserved: a
configured provider of that name is refused at boot.

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
