# Glovo MCP resource: authentication plumbing (M1a slice 1)

This slice ships feature-off. It adds no route, no MCP tool and no metadata
document, and it mints no Glovo token.

## Resource
`GLOVO_MCP_RESOURCE` (default empty = disabled; intended value
`https://glovo.mctl.ai/mcp`). The boot is refused for a value that is not an
absolute https URL without a fragment, or that names this API or
`OAUTH_SUPPORT_RESOURCE`.

While set, `/oauth/authorize` and `/oauth/token` answer `invalid_target` for
that resource (`auth.ErrGlovoNotReady`), and nothing is stored or signed.

## Verification
Order of audience classes: Glovo (exact), support, API. A token whose `aud`
contains the Glovo resource is accepted only if `aud` is exactly that one
value (issuer is the usual `BaseURL`); any other mix is `aud_mismatch`.
A Glovo-audience token gets 401 `invalid_token` on every authenticated route
(`glovoAudienceGate`, empty allowlist) and cannot mint a support token.

## Gate and errors
`glovo.Gate.Authorize` returns `not_ready` (HTTP 503) while closed, and when
open `not_authorized` (HTTP 403) for anything but a Glovo-audience caller with
a resolved principal. Envelope: `{"error": "...", "error_description": "..."}`.
`glovo.Default` is closed at compile time. No tenant is inferred.

## Worker identity
`service:mctl-glovo-worker` (`auth.GlovoWorkerUserID`) is reserved and
unissued: `IsGlovoWorker()` is always false; `MCTL_GLOVO_WORKER_TOKEN` is not read.

## Next
Slice 2: connection domain and store.
