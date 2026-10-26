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

`OAUTH_JWT_SECRET` stays required even after HS256 is drained: refresh-token
derivation (`deriveSuccessorRefreshToken`) uses it as key material.

Key set shape (PKCS#8 private, PKIX public PEM):

    {"active":"2026-11a","keys":[
      {"kid":"2026-11a","alg":"EdDSA","private_key_pem":"..."},
      {"kid":"2026-10a","alg":"EdDSA","public_key_pem":"...","retired_at":"2026-11-02T10:00:00Z"}]}

A foreign `aud` is always refused. An aud-less token is accepted only if it
is HS256 and `OAUTH_JWT_REQUIRE_AUD` is false; asymmetric tokens always need `aud`.

## Rollout

Production is mctl-gitops `bootstrap/templates/mctl-platform/mctl-api.yaml`
(2 replicas). Env changes take effect only after a rollout of both replicas.

| Step | Change | Watch before the next step |
|---|---|---|
| A | Deploy with defaults. `aud` minted and enforced. | `oauth_jwt_audless_accepted_total` stops increasing after at least one token TTL |
| B | `OAUTH_JWT_REQUIRE_AUD=true` | |
| C0 | Write the Vault property under `platform/mctl-api/oauth` with `vault kv patch` (never `put`), then add a `secretKey`/`remoteRef` entry for `OAUTH_JWT_SIGNING_KEYS` to `bootstrap/templates/mctl-platform/mctl-api-secrets.yaml` in a separate mctl-gitops PR. The ExternalSecret maps keys one by one, so a Vault write alone never reaches the pod. | The env var is present on both replicas |
| C | `OAUTH_JWT_SIGNING_ALG=EdDSA` (only after C0 is live) | `oauth_jwt_verifications_total{alg="EdDSA",result="ok"}` rises |
| D | `OAUTH_JWT_ACCEPT_HS256=false` | `oauth_jwt_verifications_total{alg="HS256",result="ok"}` stays flat for one TTL |
| E | Only after A is everywhere: other services may mint tokens with `aud=https://mcp.mctl.ai` | |

Every key-set change needs an ExternalSecret refresh (up to 1h or a force
sync) plus a rollout of both replicas.

## Rotation

In one `vault kv patch` of the same property, add the new key as `active` and
move the old one to retained with `retired_at=now`. After the refresh and
rollout the old key stays in JWKS and verifiable for
`OAUTH_JWT_KEY_RETENTION`, then drops out. Deleting the entry earlier revokes
it immediately.

## Rollback

Revert in reverse order: `OAUTH_JWT_ACCEPT_HS256=true`, then
`OAUTH_JWT_SIGNING_ALG=HS256`, then `OAUTH_JWT_REQUIRE_AUD=false`. Keep the
EdDSA key as retained for one retention window so issued tokens keep validating.
