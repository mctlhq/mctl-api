# Access-token signing, audience and JWKS

Access tokens minted by the mctl-api OAuth server carry `aud` (default
`SELF_URL`) and are verified for it. Asymmetric signing (EdDSA, ES256) is
optional and publishes a JWKS at `/.well-known/jwks.json`, advertised as
`jwks_uri` in `/.well-known/oauth-authorization-server`.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `OAUTH_ACCESS_TOKEN_AUDIENCE` | `SELF_URL` | `aud` minted and required |
| `OAUTH_JWT_SIGNING_ALG` | `HS256` | `HS256`, `EdDSA` or `ES256` |
| `OAUTH_JWT_SIGNING_KEYS` | unset | JSON key set (below); required for EdDSA/ES256; a present but malformed value refuses boot |
| `OAUTH_JWT_KEY_RETENTION` | `2h` (raised to the token TTL if longer) | how long a retired key stays verifiable and published; must be at least `OAUTH_TOKEN_TTL` |
| `OAUTH_JWT_ACCEPT_HS256` | `true` | `false` refuses every HS256 token before any HMAC; refused at boot while the signing alg is HS256 |
| `OAUTH_JWT_REQUIRE_AUD` | `false` | `true` ends the grace for aud-less HS256 tokens |
| `OAUTH_SUPPORT_RESOURCE` | `https://support.mctl.ai` | RFC 8707 resource of the support agent; set empty to disable it |

`OAUTH_JWT_SECRET` stays required even after HS256 is drained: refresh-token
derivation (`deriveSuccessorRefreshToken`) uses it as key material.

Key set shape (PKCS#8 private, PKIX public PEM):

    {"active":"2026-11a","keys":[
      {"kid":"2026-11a","alg":"EdDSA","private_key_pem":"..."},
      {"kid":"2026-10a","alg":"EdDSA","public_key_pem":"...","retired_at":"2026-11-02T10:00:00Z"}]}

A foreign `aud` is always refused. An aud-less token is accepted only if it
is HS256 and `OAUTH_JWT_REQUIRE_AUD` is false; asymmetric tokens always need `aud`.

## Rollout

Production is mctl-gitops
`platform-gitops/bootstrap/templates/mctl-platform/mctl-api.yaml` (2
replicas). An env change in that file rolls both replicas by itself. A change
that reaches the pod only through `mctl-api-secrets` (a new mapping, a Vault
write) does not: `envFrom` is read at container start, so bump
`ROLLOUT_MARKER` in the same file, in its own PR, after the ExternalSecret
has synced.

| Step | Change | Watch before the next step |
|---|---|---|
| A | Deploy with defaults. `aud` minted and enforced. | `oauth_jwt_audless_accepted_total` stops increasing after at least one token TTL |
| B | `OAUTH_JWT_REQUIRE_AUD=true` | |
| C0 | Three changes, in this order. (1) Write the Vault property under `platform/mctl-api/oauth` with `vault kv patch` (never `put`). (2) In a separate mctl-gitops PR, merged only after (1), add a `secretKey`/`remoteRef` entry for `OAUTH_JWT_SIGNING_KEYS` to `platform-gitops/bootstrap/templates/mctl-platform/mctl-api-secrets.yaml`. (3) Once the ExternalSecret reports `SecretSynced`, bump `ROLLOUT_MARKER`. | The env var is present on both replicas, `oauth_jwt_signing_keys{state="active"}` is 1 on each, and `/.well-known/jwks.json` serves the public key |
| C | `OAUTH_JWT_SIGNING_ALG=EdDSA` (only after C0 is live) | `oauth_jwt_verifications_total{alg="EdDSA",result="ok"}` rises |
| D | `OAUTH_JWT_ACCEPT_HS256=false` | `oauth_jwt_verifications_total{alg="HS256",result="ok"}` stays flat for one TTL |
| E | Not part of this rollout: minting any audience other than `OAUTH_ACCESS_TOKEN_AUDIENCE` (for example `https://mcp.mctl.ai`) is delivered by the MCP gateway epic, mctlhq/.github#236 (G1 #237, G2 #238) | |

The ordering inside C0 matters:

- The ExternalSecret maps keys one by one, so a Vault write alone never
  reaches the pod.
- ESO fails the whole ExternalSecret when one `remoteRef` does not resolve.
  Merging the mapping before the Vault property exists stops the sync of
  every key in `mctl-api-secrets`, `OAUTH_JWT_SECRET` and `DB_PASSWORD`
  included.
- Pipe the key set into `vault kv patch ... jwt-signing-keys=-` from the
  command that builds it, so no private key lands in a file, an argument or
  shell history. Store compact JSON with no trailing newline: the stored
  value is then byte-identical to what was checked. Before the mapping PR,
  parse the stored value with the deployed release's
  `parseAccessTokenKeySet`, because a malformed value refuses boot.

Read the gates as `sum by (alg,result)(...{namespace="mctl-api"})` and
check pod start times: a restart resets the counters, which can hide a rise
inside a "flat" window. After D, HS256 shows up only as
`result="alg_refused"`.

Every key-set change needs an ExternalSecret refresh (up to 1h or a force
sync) plus a `ROLLOUT_MARKER` bump.

## Rotation

In one `vault kv patch` of the same property, add the new key as `active` and
move the old one to retained with `retired_at=now`. After the refresh and
rollout the old key stays in JWKS and verifiable for
`OAUTH_JWT_KEY_RETENTION`, then drops out. Deleting the entry earlier revokes
it immediately.

## Rollback

Revert in reverse order, one mctl-gitops PR per step:

1. Delete `OAUTH_JWT_ACCEPT_HS256` (back to `true`).
2. Delete `OAUTH_JWT_SIGNING_ALG` (back to `HS256`).
3. Delete `OAUTH_JWT_REQUIRE_AUD` (back to `false`).

Step 1 must be live before step 2: boot refuses `OAUTH_JWT_SIGNING_ALG=HS256`
while `OAUTH_JWT_ACCEPT_HS256=false`, so reverting the alg first leaves the
new replicas failing to start. Both lines can also go in one PR, since each
new replica then boots with both defaults.

Issued EdDSA tokens keep verifying after step 2 without touching Vault:
asymmetric keys from `OAUTH_JWT_SIGNING_KEYS` verify regardless of the
signing alg, and the active key never expires. To retire the EdDSA key, patch
it to retained (`retired_at` set, `active` left empty), refresh and bump
`ROLLOUT_MARKER`; it then verifies for one `OAUTH_JWT_KEY_RETENTION` window
and drops out. Keep the `OAUTH_JWT_SIGNING_KEYS` mapping until then.

## Resource indicators and the support audience

`/oauth/authorize` and `/oauth/token` read the RFC 8707 `resource`
parameter (at most one value):

- absent, or the API audience, the base URL or `<base URL>/mcp`: the default
  `aud` (`OAUTH_ACCESS_TOKEN_AUDIENCE`), exactly as before;
- `OAUTH_SUPPORT_RESOURCE` (default `https://support.mctl.ai`): an access
  token whose `aud` is that single string;
- anything else, or a malformed or repeated value: `invalid_target`. At
  `/authorize` it is a redirect error; at `/token` it is HTTP 400 and the
  authorization code or refresh token is not consumed.

A code or refresh session keeps the resource it was issued for; a `/token`
request naming a different one is `invalid_target`. Sessions that predate
this are the default resource.

A support-audience token passes verification but is accepted on only
`GET /api/v1/whoami`, `POST /api/v1/work-items`,
`POST /api/v1/work-items/{id}/executions` and `POST /api/v1/agent-run-tokens`.
Every other route, `/mcp` included, answers 401 `invalid_token`.

`GET /api/v1/whoami` returns `"audience"`, a JSON array of the token's verified
`aud` values, for access tokens minted by this server. It is omitted for every
other credential. mctl-support uses it to refuse tokens minted for the API.
Setting `OAUTH_SUPPORT_RESOURCE=""` makes the support resource
`invalid_target` and refuses support-audience tokens at verification.
