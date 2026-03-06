# mctl-api

REST API + MCP server for the mctl.ai platform. Exposes platform operations (deploy services, create workspaces, provision databases) as HTTP endpoints and MCP tools for AI clients.

## Architecture

```
Claude Desktop / Cursor / Copilot ──(MCP)──┐
mctl CLI / Backstage               ──(REST)──┤──► mctl-api ──► Argo Workflows ──► GitOps ──► ArgoCD
mctl-mcp (stdio)                   ──(REST)──┘                                              └──► K8s
```

## Auth

Two token types are accepted:

| Token type | Detection | Validation |
|---|---|---|
| GitHub token | no dots | GitHub API → tenant groups from gitops |
| Dex JWT | 3 dot-separated parts | Dex JWKS → groups from token claims |

Get a GitHub token: `gh auth token`

## MCP: Claude Desktop via Streamable HTTP (recommended)

No local binary needed. Uses the current MCP spec transport — single HTTP endpoint, auth on every request, works cleanly through reverse proxies.

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": {
        "Authorization": "Bearer <your-github-token>"
      }
    }
  }
}
```

Get token: `gh auth token`

Also works via `api.mctl.me`:
```json
"url": "https://api.mctl.me/mcp"
```

Restart Claude Desktop — it will connect and expose 8 platform tools.

## MCP: Claude Desktop via stdio (local binary)

```bash
go install github.com/mctlhq/mctl-api/cmd/mcp@latest
```

```json
{
  "mcpServers": {
    "mctl": {
      "command": "/Users/<you>/go/bin/mcp",
      "env": {
        "MCTL_API_URL": "https://api.mctl.ai"
      }
    }
  }
}
```

The binary picks up `gh auth token` automatically if `MCTL_API_TOKEN` is not set.

## MCP: Cursor IDE

Settings → Cursor Settings → MCP → Add server:

```json
{
  "mcpServers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": {
        "Authorization": "Bearer <your-github-token>"
      }
    }
  }
}
```

## MCP: VS Code (GitHub Copilot)

Create `.vscode/mcp.json` in your project (or use the global MCP settings):

```json
{
  "servers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": {
        "Authorization": "Bearer ${input:mctlToken}"
      }
    }
  },
  "inputs": [
    {
      "id": "mctlToken",
      "type": "promptString",
      "description": "GitHub token (run: gh auth token)",
      "password": true
    }
  ]
}
```

VS Code will prompt for the token once and cache it in the session.

Requires VS Code ≥ 1.99 with GitHub Copilot Chat extension.

## MCP: Windsurf (Codeium)

Settings → Windsurf Settings → MCP → Add server (same format as Cursor):

```json
{
  "mcpServers": {
    "mctl": {
      "type": "http",
      "url": "https://api.mctl.ai/mcp",
      "headers": {
        "Authorization": "Bearer <your-github-token>"
      }
    }
  }
}
```

## MCP: Gemini CLI

Add to `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "mctl": {
      "httpUrl": "https://api.mctl.ai/mcp",
      "headers": {
        "Authorization": "Bearer <your-github-token>"
      }
    }
  }
}
```

## MCP: Continue.dev

Add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "mctl",
      "transport": {
        "type": "streamable-http",
        "url": "https://api.mctl.ai/mcp",
        "headers": {
          "Authorization": "Bearer <your-github-token>"
        }
      }
    }
  ]
}
```

## Available Tools

**Read (safe, no confirmation needed):**

| Tool | What it does |
|---|---|
| `mctl_list_tenants` | List all team workspaces with quotas |
| `mctl_list_services` | List services, optional `team` filter |
| `mctl_get_service_status` | ArgoCD health + sync state for a service |
| `mctl_get_workflow_status` | Status and logs of an Argo Workflow run |
| `mctl_get_resource_usage` | CPU/memory/pods quota for a team |

**Write (trigger Argo Workflows):**

| Tool | What it does |
|---|---|
| `mctl_deploy_service` | Onboard, deploy, or update-config a service |
| `mctl_create_tenant` | Create team workspace with namespace, quotas, Vault scope |
| `mctl_provision_database` | Provision PostgreSQL on shared CNPG cluster |

## Example conversations

```
"What teams exist on the platform?"
→ mctl_list_tenants

"Is payment-api healthy?"
→ mctl_get_service_status(team="billing", service="payment-api")

"Create a workspace for the data team"
→ mctl_create_tenant(tenant_name="data", display_name="Data Team")

"Deploy auth-service v2.1.0 for the platform team"
→ mctl_deploy_service(action="deploy", team_name="platform", component_name="auth-service", git_tag="v2.1.0")

"Did the deploy finish?"
→ mctl_get_workflow_status(workflow_name="deploy-service-abc123")
```

## REST API

```bash
# Health
curl https://api.mctl.ai/healthz

# List tenants (GitHub token)
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/tenants

# List services
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/services

# Service status
curl -H "Authorization: Bearer $(gh auth token)" https://api.mctl.ai/api/v1/status/billing/payment-api

# Trigger operation
curl -H "Authorization: Bearer $(gh auth token)" \
     -H "Content-Type: application/json" \
     -d '{"team_name":"billing","component_name":"payment-api","action":"deploy","git_tag":"v1.2.0"}' \
     https://api.mctl.ai/api/v1/operations/deploy-service/execute
```

## Local Development

```bash
# Run API against local gitops clone
make run

# Run MCP stdio server pointing at local API
make run-mcp

# Both together
make run &
make run-mcp
```

Auth is bypassed locally (`AUTH_REQUIRED` defaults to `false` when unset — set `AUTH_REQUIRED=true` to test auth).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `GITOPS_REPO_URL` | `https://github.com/mctlhq/mctl-core.git` | GitOps repo to clone |
| `GITOPS_LOCAL_PATH` | `/tmp/mctl-core` | Local clone path |
| `ARGOCD_URL` | `https://ops.mctl.me` | ArgoCD API URL |
| `ARGOCD_TOKEN` | — | ArgoCD API token (from Vault) |
| `ARGO_WORKFLOWS_NAMESPACE` | `argo-workflows` | Namespace for workflow submission |
| `GITHUB_ORG` | `mctlhq` | Required GitHub org for token auth |
| `ADMIN_USERS` | — | Comma-separated GitHub logins with admin access |
| `DEX_ISSUER_URL` | `https://ops.mctl.me/api/dex` | Dex OIDC issuer for JWT auth |
| `DEX_CLIENT_ID` | — | Dex client ID (informational) |
| `SELF_URL` | `https://api.mctl.ai` | Public base URL (advertised in MCP SSE) |
| `AUTH_REQUIRED` | `true` | Set to `false` to bypass auth in dev |
| `BACKSTAGE_URL` | — | Backstage URL for catalog sync |
| `BACKSTAGE_TOKEN` | — | Backstage service token |

## Deployment

ArgoCD syncs from `platform-gitops/apps/templates/mctl-api.yaml`. Secrets come from Vault via ExternalSecret.

Vault secrets to create before first deploy:

```bash
# ArgoCD API token (Settings → Accounts → mctl-api → Generate Token)
vault kv put platform/mctl-api/argocd-token token="<token>"

# Backstage service token
vault kv put platform/mctl-api/backstage-token token="<token>"

# Dex SSO client secret (must match argocd/values.yaml staticClients)
vault kv put platform/mctl-api/sso client-id="mctl-api" client-secret="<random-32-chars>"
```

Image is built and pushed to `ghcr.io/mctlhq/mctl-api:latest` on every push to `main`.
