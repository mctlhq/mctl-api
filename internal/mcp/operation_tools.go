package mcp

// operationTools maps every registry operation with RequiresConfirm: true to
// the MCP tool that submits it. The parity tests use it to prove that each
// such tool is gated by requireConfirm and forwards confirm="yes", so the
// registry flag cannot silently stop meaning anything on the MCP surface.
var operationTools = map[string]string{
	"create-tenant":      "mctl_create_tenant",
	"provision-database": "mctl_provision_database",
	"retire-service":     "mctl_retire_service",
	"delete-tenant":      "mctl_delete_tenant",
}
