# mctl-api

Go REST API + MCP server. Control plane for the mctl platform.

## Language & Tools
- Go 1.25, chi/v5 router, mcp-go
- `go fmt`, `go vet`, `golangci-lint` before committing
- Structured logging with `slog` (JSON handler)

## Conventions
- Interface-based design for testability (see `internal/api/interfaces.go`)
- Error handling: return errors with `fmt.Errorf("context: %w", err)`, never panic
- Context propagation for all I/O operations
- `writeError()` / `writeJSON()` helpers for HTTP responses
- Package structure: `internal/` with focused packages (api, auth, gitops, mcp, operations, etc.)

## Testing
- Unit tests: `go test ./...`
- E2E tests: `cd e2e && go test -v`
- MCP tool count must match `server_test.go` expectation when adding/removing tools

## Key Paths
- `cmd/api/main.go` — entrypoint, env var defaults
- `internal/mcp/server.go` — MCP tool definitions
- `internal/api/router.go` — route definitions
- `internal/auth/` — triple-token auth (GitHub, Dex, OAuth)
- `helm/` — Helm chart for deployment
