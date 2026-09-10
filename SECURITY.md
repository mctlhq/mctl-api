# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Email:** security@mctl.ai

**Response time:** We will acknowledge your report within 48 hours and provide a detailed response within 5 business days.

**Please do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

## Supported Versions

Only the latest release is supported with security updates.

## Scope

This policy applies to all repositories in the mctlhq organization:
- mctl-api
- mctl-web
- mctl-gitops
- mctl-portal
- mctl-agent

## OAuth clients

The authorization server is public-client only: a client proves possession of an authorization code with PKCE (S256), never with a credential, and no configuration surface accepts a client secret.

Clients reach the server in one of two ways. RFC 7591 dynamic registration issues a random `client_id` held in memory for `defaultClientRegistrationTTL` and capped at `MaxRegisteredClients`; a registration therefore does not survive a pod restart and is the right fit for clients that re-register on their own (claude.ai, ChatGPT). `OAUTH_PREREGISTERED_CLIENTS` seeds static clients for a counterpart that cannot re-register — the Cloudflare MCP portal stores one `client_id` per upstream at configuration time and expects it to keep working. Static clients are outside the TTL and the eviction cap, a dynamic registration can never be assigned a static id, and each one trusts exactly the callbacks it lists, byte for byte: the global `OAUTH_ALLOWED_REDIRECT_URIS` allowlist plays no part, so onboarding one counterpart does not loosen redirect acceptance for anyone else. The same shape rules apply at startup that `IsRedirectURIAllowed` relies on at runtime — absolute URL, `https` or loopback `http`, no fragment, no userinfo — and a value that fails them, or carries a key the decoder does not know, refuses the boot rather than seeding a client that silently never works.

