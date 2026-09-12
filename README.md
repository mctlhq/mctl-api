# mctl-api

Control plane API for the mctl.ai Internal Developer Platform — dual-protocol (REST + MCP) access to manage services, workspaces, databases, previews, and platform operations.

## What It Does

mctl-api is the central gateway for the mctl.ai platform. It exposes every platform operation — deploying services, creating team workspaces, provisioning databases, managing custom domains — as both REST endpoints and MCP tools. AI coding assistants (Claude, Copilot, Cursor, Gemini, and others) connect via the MCP protocol, while Backstage and CLI tools use the REST API. All write operations are executed through Argo Workflows and reconciled by ArgoCD through a GitOps repository.

## Architecture

```
AI Clients (Copilot CLI / Claude / Cursor / VS Code / Windsurf / Gemini / Continue.dev)
    │
    ▼
MCP Server (/mcp endpoint, Streamable HTTP)
    │
    ▼
REST API (/api/v1/*)  ◄── Backstage / CLI / HTTP clients
    │
    ├──► Argo Workflows    (submits deploy/provision/rollback jobs)
    ├──► GitOps Repo       (reads service configs, commits changes)
    ├──► ArgoCD            (sync status, health checks)
    ├──► Kubernetes        (resource quota usage)
    ├──► Loki              (service log queries)
    └──► PostgreSQL        (audit log)
```

## Tech Stack

| Category | Details |
|----------|---------|
| Language | Go 1.25 |
| HTTP Router | chi v5.2 |
| MCP Server | mcp-go v0.31 (Streamable HTTP transport) |
| Auth | GitHub token resolution, Dex/OIDC JWT, OAuth 2.0 PKCE |
| Database | PostgreSQL via pgx v5.9 (audit logs) |
| Kubernetes | client-go v0.32 (quota reader) |
| Rate Limiting | httprate v0.15 (300 req/min authenticated including POST /mcp, loopback MCP-internal REST excluded from that cap, 20 req/min write) |
| Container Registry | ghcr.io/mctlhq/mctl-api |
| Linting | golangci-lint (errcheck, govet, staticcheck, gosec, bodyclose) |

## Project Structure

```
mctl-api/
├── cmd/api/main.go              # Entry point, server bootstrap
├── internal/
│   ├── api/                     # REST handlers & router
│   │   ├── handlers_read.go     # Read operations (list, status, config)
│   │   ├── handlers_write.go    # Write operations (deploy, create, retire)
│   │   ├── handlers_domains.go  # Custom domain management
│   │   ├── handlers_repos.go    # Repository access management
│   │   ├── oauth_handlers.go    # OAuth 2.0 Authorization Code + PKCE
│   │   └── router.go            # Route definitions & middleware
│   ├── auth/                    # GitHub + OIDC + OAuth authentication
│   ├── mcp/                     # MCP server implementation (tool registry)
│   ├── operations/              # Platform operation registry & executor
│   ├── argocd/                  # ArgoCD API client
│   ├── gitops/                  # GitOps repo reader (clone, parse values)
│   ├── audit/                   # Audit logging (PostgreSQL-backed)
│   ├── k8s/                     # Kubernetes quota reader
│   ├── loki/                    # Loki log query client
│   └── openapi/                 # Embedded OpenAPI spec
├── e2e/                         # End-to-end tests (build tag: e2e)
├── helm/                        # Kubernetes Helm chart
├── Dockerfile                   # Multi-stage Alpine build
├── Makefile                     # Dev commands (run, test, lint, build)
├── .golangci.yml                # Linter configuration
├── .env.example                 # Environment variable template
├── mcp-config.example.json      # MCP client config examples
└── .github/workflows/build.yml  # CI/CD pipeline
```

## Getting Started

### Prerequisites

- Go 1.25+
- GitHub CLI (`gh`) — for obtaining auth tokens
- Access to the `mctlhq` GitHub organization

### Local Development

```bash
# Run API against local gitops clone
make run

# Run MCP stdio server pointing at local API
make run-mcp

# Both together
make run &
make run-mcp
```

Auth is bypassed locally (`AUTH_REQUIRED` defaults to `false` when unset). Set `AUTH_REQUIRED=true` to test authentication.

### Docker

```bash
docker build -t mctl-api .
docker run -p 8080:8080 mctl-api
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | HTTP server port | `8080` | No |
| `AUTH_REQUIRED` | Enable authentication | `true` | No |
| `ADMIN_USERS` | Admin GitHub usernames (comma-separated) | — | No |
| `GITOPS_REPO_URL` | GitOps repository URL | `https://github.com/mctlhq/mctl-gitops.git` | No |
| `GITOPS_BRANCH` | GitOps branch | `main` | No |
| `GITOPS_LOCAL_PATH` | Local cache path for gitops clone | `/tmp/mctl-gitops` | No |
| `GITHUB_APP_TOKEN_FILE` | Path to a mounted GitHub App installation token. Takes precedence over `GITOPS_REPO_TOKEN` and `GITOPS_ACTIONS_TOKEN`, and is re-read per use so a rotation is picked up without a restart. | — | No |
| `GITOPS_REPO_TOKEN` | GitHub token for HTTPS clone. Fallback when `GITHUB_APP_TOKEN_FILE` is unset; read once at startup, so only for credentials that do not rotate. | — | No |
| `GITOPS_SSH_KEY_PATH` | SSH key path for git clone | — | No |
| `ARGOCD_URL` | ArgoCD API endpoint | `https://ops.mctl.ai` | No |
| `ARGOCD_TOKEN` | ArgoCD auth token (from Vault) | — | Yes |
| `ARGO_WORKFLOWS_NAMESPACE` | Kubernetes namespace for workflows | `argo-workflows` | No |
| `GITHUB_ORG` | Required GitHub organization | `mctlhq` | No |
| `DEX_ISSUER_URL` | OIDC issuer URL | `https://ops.mctl.ai/api/dex` | No |
| `DEX_CLIENT_ID` | JWT audience for Dex | — | No |
| `SELF_URL` | Public base URL | `https://api.mctl.ai` | No |
| `ALLOWED_ORIGINS` | CORS allowed origins | — | No |
| `OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth app client ID | — | No |
| `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret | — | No |
| `OAUTH_JWT_SECRET` | JWT signing secret for OAuth tokens | — | No |
| `OAUTH_ALLOWED_REDIRECT_URIS` | Allowed OAuth redirect URIs | — | No |
| `OAUTH_PREREGISTERED_CLIENTS` | JSON array of static public OAuth clients for counterparts that cannot register dynamically (the Cloudflare MCP portal): `[{"client_id":"…","client_name":"…","redirect_uris":["https://…"]}]`. Exact redirect match, no secret field, never evicted; a malformed value or an unknown key refuses startup | — | No |
| `AUDIT_DB_URL` | PostgreSQL connection string (falls back to in-memory). `sslmode=disable` is upgraded to `require`, or `verify-full` when a CNPG CA is mounted. | — | No |
| `TRUSTED_PROXY_CIDRS` | Comma-separated Traefik CIDRs/IPs trusted for `X-Forwarded-For` on audit events | — | No |
| `ALLOW_INSECURE_DB` | Permit `sslmode=disable` (tests/local only) | — | No |
| `BACKSTAGE_URL` | Backstage catalog URL | — | No |
| `BACKSTAGE_TOKEN` | Backstage service token, used only for tenant catalog sync (`notifyBackstage`) — no longer used by `/api/v1/domains*`, which is mctl-api's own registry | — | No |
| `BACKSTAGE_GITHUB_APP_CONNECT_TOKEN` | Backstage service token, scoped to the `github-app-connect` plugin (repos list/sync/install-url) | — | No |
| `DOMAINS_DB_URL` | PostgreSQL connection string for the custom domains registry (falls back to `AUDIT_DB_URL`). Without either, `/api/v1/domains*` returns 503. | — | No |
| `PLATFORM_DOMAIN` | The platform's own domain. Hostnames equal to or ending in `.<PLATFORM_DOMAIN>` are rejected by `POST /api/v1/domains` — those stay GitOps-only via `ingress.hosts`. | `mctl.ai` | No |
| `DNS_RESOLVER_ADDR` | `host:port` of the recursive resolver used to verify custom domain TXT/CNAME records | `1.1.1.1:53` | No |
| `LOKI_URL` | Loki base URL for log queries | — | No |

## API / Endpoints

### Authentication

Three authentication methods are supported:

| Method | Detection | Validation |
|--------|-----------|------------|
| GitHub personal token | No dots in token | GitHub API → resolve org membership |
| Dex/OIDC JWT | 3 dot-separated parts | JWKS validation → groups from claims |
| OAuth 2.0 + PKCE | Authorization Code flow | For Claude.ai custom connectors |

Get a token: run `gh auth token` or visit [mctl.ai/mcp](https://mctl.ai/mcp) to sign in and copy a pre-filled config. Your GitHub account must be a member of the `mctlhq` organization.

### REST API

```bash
# Health check
curl https://api.mctl.ai/healthz

# List tenants
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/tenants

# List services
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/services

# Service status
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/status/billing/payment-api

# Service logs (last 50 lines, past 30 minutes)
curl -H "Authorization: Bearer $(gh auth token)" \
     "https://api.mctl.ai/api/v1/logs/billing/payment-api?lines=50&since=30m"

# Trigger a deploy
curl -H "Authorization: Bearer $(gh auth token)" \
     -H "Content-Type: application/json" \
     -d '{"team_name":"billing","component_name":"payment-api","action":"deploy","git_tag":"v1.2.0"}' \
     https://api.mctl.ai/api/v1/operations/deploy-service/execute
```

### OpenAPI Documentation

| URL | Description |
|-----|-------------|
| `https://api.mctl.ai/openapi.yaml` | Raw OpenAPI 3.0 spec |
| `https://api.mctl.ai/docs` | Interactive Swagger UI |

### MCP Setup

The MCP endpoint is available at `https://api.mctl.ai/mcp` (Streamable HTTP). All clients use the same auth — a GitHub token passed as a Bearer header.

**Copilot CLI** — add to `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": { "Authorization": "Bearer <your-github-token>" }
    }
  }
}
```

**Claude Desktop** (Streamable HTTP) — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": { "Authorization": "Bearer <your-github-token>" }
    }
  }
}
```

**Claude Desktop** (stdio, local binary):

```bash
go install github.com/mctlhq/mctl-api/cmd/mcp@latest
```

```json
{
  "mcpServers": {
    "mctl": {
      "command": "/Users/<you>/go/bin/mcp",
      "env": { "MCTL_API_URL": "https://api.mctl.ai" }
    }
  }
}
```

**Cursor** — Settings → Cursor Settings → MCP → Add server (same JSON as Copilot CLI).

**VS Code** — create `.vscode/mcp.json`:

```json
{
  "servers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": { "Authorization": "Bearer ${input:mctlToken}" }
    }
  },
  "inputs": [
    { "id": "mctlToken", "type": "promptString", "description": "GitHub token (run: gh auth token)", "password": true }
  ]
}
```

**Windsurf** — Settings → Windsurf Settings → MCP → Add server (same JSON as Copilot CLI).

**Gemini CLI** — add to `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "mctl": {
      "httpUrl": "https://api.mctl.ai/mcp",
      "headers": { "Authorization": "Bearer <your-github-token>" }
    }
  }
}
```

**Continue.dev** — add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "mctl",
      "transport": {
        "type": "streamable-http",
        "url": "https://api.mctl.ai/mcp",
        "headers": { "Authorization": "Bearer <your-github-token>" }
      }
    }
  ]
}
```

### MCP Tools

**Read operations** (safe, no side effects):

| Tool | Description |
|------|-------------|
| `mctl_list_tenants` | List all team workspaces with quotas |
| `mctl_list_services` | List services, optional team filter |
| `mctl_get_tenant` | Get workspace details and members |
| `mctl_get_service_status` | ArgoCD health + sync state |
| `mctl_get_service_config` | Full service config from GitOps repo |
| `mctl_get_resource_usage` | Live CPU/memory/pods from K8s ResourceQuota |
| `mctl_get_service_logs` | Recent log lines from Loki |

**Write operations** (trigger Argo Workflows):

| Tool | Description |
|------|-------------|
| `mctl_deploy_service` | Onboard, deploy, or update-config a service |
| `mctl_create_tenant` | Create team workspace (namespace, quotas, Vault) |
| `mctl_provision_database` | Provision PostgreSQL on shared CNPG cluster |
| `mctl_rollback_service` | Roll back to a previous image tag |
| `mctl_retire_service` | Permanently remove a service |
| `mctl_create_preview` / `mctl_delete_preview` | Ephemeral preview environments |
| `mctl_add_custom_domain` / `mctl_remove_custom_domain` | Custom domain management |
| `mctl_list_repos` / `mctl_sync_repos` / `mctl_grant_repo_access` | Repository access |

## Testing

```bash
# Unit tests
make test

# Lint
make lint

# End-to-end tests (requires running platform)
go test -tags=e2e ./e2e/ -run TestE2E_FullPlatformSmokeTest
```

Linting uses golangci-lint with errcheck, govet, staticcheck, gosec, bodyclose, and other checkers configured in `.golangci.yml`.

## CI/CD

GitHub Actions:

- **validate.yml** (pull requests): golangci-lint, `go build`, `go test`
- **security.yml**: govulncheck and a Trivy filesystem scan (CRITICAL, fail closed)
- **release-please.yml**: tagged releases, GHCR image, gitops bump
- **Registry:** `ghcr.io/mctlhq/mctl-api`
- **Dependabot:** weekly `go.mod`, GitHub Actions, and Dockerfile updates

## Deployment

Deployed to Kubernetes via Helm chart (`helm/`). ArgoCD syncs the desired state from the mctl-gitops repository.

**Domain:** `api.mctl.ai`

Vault secrets required before first deploy:

```bash
# ArgoCD API token
vault kv put platform/mctl-api/argocd-token token="<token>"

# Backstage service token
vault kv put platform/mctl-api/backstage-token token="<token>"

# Dex SSO client secret
vault kv put platform/mctl-api/sso client-id="mctl-api" client-secret="<secret>"
```

## Release Process

```bash
git tag 0.2.0 && git push origin 0.2.0
# → CI builds ghcr.io/mctlhq/mctl-api:0.2.0
# → CI commits new tag to mctl-gitops → ArgoCD deploys
```

Tags use **no `v` prefix**. Every push to `main` also builds a `latest` image for local development.

## Related Projects

| Repository | Description |
|------------|-------------|
| [mctl-gitops](https://github.com/mctlhq/mctl-gitops) | GitOps repository — Helm values, ArgoCD app definitions |
| [mctl-portal](https://github.com/mctlhq/mctl-portal) | Web portal for token management and MCP config generation |
| [mctl-web](https://github.com/mctlhq/mctl-web) | Marketing site (mctl.ai) |
| [mctl-agent](https://github.com/mctlhq/mctl-agent) | Platform agent components |

## License

Apache 2.0

## Portal tool allowlist

`api.mctl.ai/mcp` is one upstream of the private aggregate portal `mcp.mctl.ai` (mctlhq/.github#35). The portal exposes a tool only when its mapping carries an explicit `enabled: true` for it and hides one it has an entry for with `enabled: false`; the mapping is kept at `default_disabled: true` plus an explicit entry for every tool. `docs/portal-allowlist.json` is the source of truth; `internal/mcp/portal_allowlist_test.go` fails the build when the set of registered tools differs from the file, when an enabled tool carries no `reason`, or when an enabled tool that is not recorded read-only in `internal/mcp/annotations_test.go` is missing from the `mutatingOnPortal` map in that test. Exposing a mutating tool is therefore a reviewed Go change naming what it changes, not a JSON edit — and it grants visibility only: the API's own authentication, team scope and role checks decide whether the call succeeds. After a release that changes the tool set, the operator re-applies the file (CI holds no Cloudflare credential):

```
read -rs CLOUDFLARE_API_TOKEN && export CLOUDFLARE_API_TOKEN   # not on the command line: the shell would record it
export CLOUDFLARE_ACCOUNT_ID=…
scripts/portal-allowlist-apply.sh --dry-run
scripts/portal-allowlist-apply.sh
```

The script refuses a file that differs from `HEAD` and runs the guard test before it touches the API, so what is applied is a committed revision the build has judged.

A portal access token carries the tool set as of its issuance; re-issue tokens after an apply.

`scripts/portal-allowlist-apply.sh --check` compares the committed file against the live portal mapping instead of writing to it: `default_disabled`, plus the enabled/disabled state of every tool the server has synced. It is held to exactly the same pre-flight as an apply or a `--dry-run` — credentials, `jq`, a git checkout, the file tracked and matching `HEAD`, `portal=mcp`/`server=api`, `go`, and the guard test — and it never issues a `PUT`, on any path, including the one where it finds disagreement:

```
scripts/portal-allowlist-apply.sh --check
```

A tool whose live state disagrees with the file prints `drift: <tool> portal=<live> file=<committed>`; a `default_disabled` disagreement prints `drift: default_disabled portal=<live> file=<committed>`; a tool the server has synced but the file has no decision for prints `drift: <tool> synced by the server with no decision in docs/portal-allowlist.json`. A tool the file decides but the server has not synced is not drift — the apply holds it back by design — and is instead named on a `held back (not synced by the server): <names>` line after the in-sync summary.

Exit codes: `0` in sync (or applied), `1` the comparison (or apply) could not be made — a pre-flight guard refused, or an API call failed, `2` a usage error, `3` the portal and the file disagree (`--check` only). Every non-zero status is a failure a caller must surface: the split between `1` and `3` exists only to say which one happened, never to make either tolerable — a job alerting on `3` alone would read an expired token or a revoked scope the same way it reads a clean portal. One documented exception to that table: a missing `jq` exits `2`, not the `1` that "could not check or apply" would otherwise imply. This is `mctl-telegram`'s landed behaviour, reproduced here so the two scripts do not disagree while it is fixed in both at once (mctlhq/mctl-telegram#635).

`--check` is operator-run today, the same as the apply: CI holds no Cloudflare credential (mctlhq/mctl-gitops#1111). A scheduled job driving both this script and `mctl-telegram`'s is tracked in mctlhq/mctl-gitops#1211.
