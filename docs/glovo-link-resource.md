# Glovo link resource: forced fresh login

`GLOVO_LINK_RESOURCE` (default empty = disabled, every other flow is
byte-identical). It is an RFC 8707 resource, distinct from the MCP, support,
API and any `OAUTH_MCP_RESOURCES` entry; the boot is refused when it equals
one of them, names this API, or is not an absolute https URL without a
fragment. It is admitted only while `GlovoReady()` holds (same gate as
`GLOVO_MCP_RESOURCE`); otherwise `invalid_target`.

For this resource only:

- `/oauth/authorize` rejects `prompt=none` (`invalid_request`) and any
  upstream other than ZITADEL.
- The ZITADEL authorize request carries `prompt=login` and `max_age=0`.
- The ZITADEL callback requires an ID token `auth_time` that is present, > 0
  and not earlier than the authorization start minus one minute; otherwise
  the client gets `access_denied` and no code is issued.
- `auth_time` travels callback -> consent entry -> code -> JWT and is minted
  into the link audience's token only; no other token carries it.
- The token has no refresh token (the `refresh_token` member is omitted), and
  a refresh grant for the resource is refused.
- This server's own bearer verification refuses the link audience (alone or
  mixed with another), so neither the API nor `/mcp` accepts a link token.
  Only the Glovo service accepts it, by checking the signature against the
  JWKS and requiring the exact `aud` and `auth_time`.
