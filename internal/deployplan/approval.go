package deployplan

// RequiredApproval is the risk matrix: what approval a plan needs before it
// may be applied. Preview update and preview onboard are reachable.
func RequiredApproval(environment string, action Action) Approval {
	if environment == EnvironmentPreview && action == ActionUpdate {
		return Approval{Required: true, Role: "owner", Reason: "preview_update_requires_approval_until_build_sandbox"}
	}
	if environment == EnvironmentPreview && action == ActionOnboard {
		return Approval{Required: true, Role: "owner", Reason: "preview_onboard_requires_approval"}
	}
	if environment == EnvironmentProduction && action == ActionPromote {
		return Approval{Required: true, Role: "owner", Reason: "promote_requires_approval"}
	}
	// Anything else is not planned by this package; fail closed.
	return Approval{Required: true, Role: "owner", Reason: "onboard_high_risk"}
}
