package telemetry

import "go.opentelemetry.io/otel/attribute"

// Span attribute keys. Names come from the platform telemetry catalog
// (mctl-docs/docs/reference/telemetry-attributes.md); no parallel names.
// Nothing here ever carries a tool argument, prompt, completion or credential.
const (
	KeyToolName         = "mctl.tool.name"
	KeyToolStatus       = "mctl.tool.status"
	KeyActorID          = "mctl.actor.id"
	KeyActorType        = "mctl.actor.type"
	KeyWorkflowID       = "mctl.workflow.id"
	KeyWorkflowRunID    = "mctl.workflow.run_id"
	KeyWorkflowType     = "mctl.workflow.type"
	KeyArgoWorkflowName = "mctl.argo.workflow.name"
	KeyExecutionID      = "mctl.execution.id"
	KeyWorkItemID       = "mctl.work_item.id"
	KeyMCPMethodName    = "mcp.method.name"

	// Not yet in the catalog: pending catalog additions (a mctl-docs PR adds
	// them).
	KeyOperationName = "mctl.operation.name"
	KeyIncidentID    = "mctl.incident.id"
)

// CatalogKeys are the keys already present in the telemetry catalog.
func CatalogKeys() []string {
	return []string{
		KeyToolName, KeyToolStatus, KeyActorID, KeyActorType,
		KeyWorkflowID, KeyWorkflowRunID, KeyWorkflowType,
		KeyArgoWorkflowName, KeyExecutionID, KeyWorkItemID, KeyMCPMethodName,
	}
}

// PendingCatalogKeys are keys shipped ahead of their catalog entry.
func PendingCatalogKeys() []string {
	return []string{KeyOperationName, KeyIncidentID}
}

// AllowedKeys is the full allowlist of span attribute keys this service emits.
func AllowedKeys() []string {
	return append(CatalogKeys(), PendingCatalogKeys()...)
}

// ToolName, ToolStatus, OperationName and IncidentID build the allowlisted
// attributes.
func ToolName(v string) attribute.KeyValue      { return attribute.String(KeyToolName, v) }
func ToolStatus(v string) attribute.KeyValue    { return attribute.String(KeyToolStatus, v) }
func OperationName(v string) attribute.KeyValue { return attribute.String(KeyOperationName, v) }
func IncidentID(v string) attribute.KeyValue    { return attribute.String(KeyIncidentID, v) }
func MCPMethod(v string) attribute.KeyValue     { return attribute.String(KeyMCPMethodName, v) }
func ActorID(v string) attribute.KeyValue       { return attribute.String(KeyActorID, v) }
func ActorType(v string) attribute.KeyValue     { return attribute.String(KeyActorType, v) }
