package deployplan

// RequiredApproval is the risk matrix: what approval a plan needs before it
// may be applied. Only preview update is reachable in this item.
func RequiredApproval(environment string, action Action) Approval {
	if environment == EnvironmentPreview && action == ActionUpdate {
		return Approval{Required: true, Role: "owner", Reason: "preview_update_requires_approval_until_build_sandbox"}
	}
	// Anything else is not planned by this package; fail closed.
	return Approval{Required: true, Role: "owner", Reason: "onboard_high_risk"}
}
