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

## Google-only guard: shadow mode

Design: Glovo self-service onboarding, section 5.1 and decision D5. The rule
being prepared is that a code for the Glovo MCP resource
(`GLOVO_MCP_RESOURCE`) or the Glovo link resource (`GLOVO_LINK_RESOURCE`) is
issued only to a customers-organization identity proven through Google. An
access token has no provider claim, so the Glovo service cannot check this;
the sign-in callback can.

This version only observes. `GLOVO_GOOGLE_ONLY_MODE` has these values:

| Value | Behaviour |
|---|---|
| `off` (default, also empty) | Nothing is evaluated, logged or counted. |
| `shadow` | Every sign-in on one of the two Glovo resources is evaluated and logged. Nothing is refused: the response, the redirect and the code are the ones `off` gives. |
| `enforce` | Not implemented. The boot is refused, like any unknown value, so a refusal that has no tests cannot be switched on. |

The owner switches the mode (a value in mctl-gitops). Resources other than
the two Glovo ones are never evaluated in any mode.

### Reading the shadow log

One line per completed sign-in on a Glovo resource, written just before the
consent page is shown:

```json
{"time":"...","level":"INFO","msg":"oauth: glovo google-only shadow","mode":"shadow","would_refuse":"true","provider":"github","resource":"mcp","principal":"prn_***AAAA"}
```

`would_refuse` is a string, not a boolean, because it has three values.

| Field | Values |
|---|---|
| `would_refuse` | `false`: the guard would let it through. `true`: it would refuse. `unknown`: the provider could not be determined, which is neither. |
| `provider` | `google`, `github`: a customers-organization identity with the identity hook's proof of that provider. `staff`: a ZITADEL identity of any other organization (staff and partner accounts). `github_legacy`: the direct GitHub upstream (`OAUTH_UPSTREAM=github` or `both`). `unknown`: see below. |
| `resource` | `mcp` or `link`. |
| `principal` | The last four characters of the principal id (`prn_***AAAA`). Compare them with your own id from `mctl_whoami`. `none` or `invalid` if no well-formed id was resolved; the raw value is never logged. |

The same decisions are counted in
`oauth_glovo_google_only_shadow_total{resource,provider,would_refuse}`.

How the provider is determined, and its limits:

- It comes from the verified ZITADEL ID token: the organization claim
  (`urn:zitadel:iam:user:resourceowner:id`) says whether this is a customers
  identity, and the identity hook's `mctl:idp` claim says which IdP proved
  it. Nothing is read from the principal store, so the line describes this
  sign-in, not every identity the principal has.
- `staff` does not say how the person authenticated. The token does not
  carry it, so a password, a passkey and an instance-level IdP are all
  `staff`.
- `unknown` is logged when no customers organization is configured (the
  provider entry has no `customers_org_id`): the callback then never reads
  the token's organization, so whether this was a Google customer was not
  observed. It is also logged for a proof naming a provider the guard does
  not list.
- A sign-in that the existing code already refuses (a customers account with
  no proven identity, an unlinked identity, a stale link sign-in) never
  reaches the guard and writes no line.
- A person who abandons the consent page still has a line: it is written at
  sign-in, not when the code is issued.

Before the mode can become enforcing, a later change has to implement the
refusal with its own tests and start the Google sign-in directly for these
resources instead of showing the chooser.
