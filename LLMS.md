# LLMS.md — mctl-api Control Plane Overview

> `mctl-api` is the Go control plane API for the mctl platform. It provides dual-protocol access (REST API + Model Context Protocol / MCP) to manage services, namespaces, databases, preview environments, and platform workflows.

## Package Architecture

- `cmd/server/`: Entrypoint, environment parsing, HTTP server initialization.
- `internal/api/`: REST handlers (`handlers_read.go`, `handlers_write.go`, `handlers_alerts.go`, `router.go`).
- `internal/auth/`: Multi-tenant OIDC/Dex JWT authentication, GitHub token validation, static service token checks (`staticServiceUser`).
- `internal/mcp/`: Native MCP server implementation exposing 54 platform tools to LLMs (Claude Code, Cursor, Antigravity).
- `internal/argoarchive/`: S3/R2 client for fetching historical Argo Workflow execution logs.
- `internal/argocd/`: ArgoCD integration for GitOps application synchronization and status checks.
- `internal/operations/`: Long-running async operation state tracking (`/api/v1/operations`).

## Authentication & RBAC

- **Dual Auth**: Supports Bearer tokens for both Dex OIDC (user JWTs) and GitHub Personal Access Tokens (PATs).
- **Service Account Auth**: `MCTL_AGENT_SERVICE_TOKEN` allows trusted in-cluster automation (e.g. `mctl-agent`) to act with `admins` group privileges.
- **Tenant Scope**: Requests are scoped to tenant groups (`admins`, `labs`, `ovk`, etc.) resolved via `internal/auth/tenant.go`.
- **Tenant Role**: Membership grants visibility; a tenant write also needs a minimum role (`viewer` < `developer` < `owner`) declared per operation as `MinRole` in `internal/operations/registry.go` and enforced by `internal/api/tenant_role.go`. The role is read per request from the tenant's `members[].role` in the gitops checkout, keyed on a GitHub login that authentication proved. An unknown or missing role is refused (403); a role that could not be read is 503. Platform admins pass every minimum.

## Key REST API Endpoints

- `GET /healthz`, `GET /readyz`: Liveness and readiness health checks. `/readyz` returns 503 only on store init failure or drain; dependency health is in the body (`checks`, `dependencies`) and the `mctl_api_dependency_up{check}` metric.
- `GET /api/v1/services`: List services across tenants.
- `GET /api/v1/workflows/{name}/logs`: Retrieve live or S3/R2 archived workflow logs.
- `POST /api/v1/incidents`: Register platform incidents (`type: workflow_failed`, `status: analyzing`).
- `POST /api/v1/incidents/resolve-by-fingerprint`: Resolve open incident matching fingerprint on workflow recovery.

## Development & Test Commands

```bash
go test ./... -v       # Run full test suite
go run ./cmd/server    # Start local server on :8080
```
