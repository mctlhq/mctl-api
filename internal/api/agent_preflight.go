package api

import (
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// Preflight check statuses. There is deliberately no path from an error or a
// missing input to statusPass: unknown is never pass.
const (
	statusPass    = "pass"
	statusFail    = "fail"
	statusUnknown = "unknown"
)

// Provider id and alias that validate-agent-platform.py hardcodes
// (MCTL_API_PROVIDER_ID / MCTL_API_REQUIRED_ALIAS).
const (
	preflightMctlAPIProviderID = "mctl-api"
	preflightMctlAPIAlias      = "mctl"
	preflightMctlToolPattern   = "mcp__mctl__*"
)

// ruleSources names, for every check, the CI rule it mirrors. The Python
// script mctl-gitops/scripts/validate-agent-platform.py stays authoritative;
// when it changes, this table is the one place that shows which Go check has
// to follow.
var ruleSources = map[string]string{
	"binding.lifecycle":            "agentregistry",
	"binding.compatibility":        "validate-agent-platform.py:648",
	"profile.budget":               "validate-agent-platform.py:263",
	"profile.timeout":              "validate-agent-platform.py:267",
	"profile.sandbox":              "validate-agent-platform.py:276,278",
	"profile.model_policy_task":    "validate-agent-platform.py:221",
	"profile.refs":                 "validate-agent-platform.py:210,214,217,260",
	"profile.approval_gates":       "validate-agent-platform.py:287,293,297",
	"profile.capability_discovery": "validate-agent-platform.py:240-253",
}

// PreflightCheck is one line of a preflight report.
type PreflightCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Source string `json:"source"`
}

// registryFacts is what the binding.* checks know about the resolved pair.
type registryFacts struct {
	// resolved is true when the facts come from a registry row.
	resolved bool
	// fromFixture is true when the lifecycles come from a release intent's
	// registryLifecycle rather than the registry.
	fromFixture   bool
	defLifecycle  string
	profLifecycle string
	// compatSatisfied is nil when nothing was resolved from the registry.
	compatSatisfied *bool
	compatRange     string
	// versionMismatch is set when the gitops profile version differs from the
	// version the intent or pin asked for.
	versionMismatch string
	// err is a registry error that was not a "not found"; binding.* is unknown.
	err error
}

func check(id, status, detail string) PreflightCheck {
	return PreflightCheck{ID: id, Status: status, Detail: detail, Source: ruleSources[id]}
}

func inList(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// evaluatePreflight runs the nine checks. spec/policy may be nil with the
// matching error; every check that needs a missing input is unknown.
func evaluatePreflight(spec *gitops.ExecutionProfileSpec, specErr error, policy *gitops.AgentPlatformPolicy, policyErr error, reg *registryFacts) []PreflightCheck {
	if reg == nil {
		reg = &registryFacts{}
	}
	specUnknown := func(id string) (PreflightCheck, bool) {
		if spec == nil {
			reason := "profile spec unavailable"
			if specErr != nil {
				reason += ": " + specErr.Error()
			}
			return check(id, statusUnknown, reason), true
		}
		return PreflightCheck{}, false
	}
	policyUnknown := func(id string) (PreflightCheck, bool) {
		if c, ok := specUnknown(id); ok {
			return c, true
		}
		if policy == nil {
			reason := "policy.yaml unavailable"
			if policyErr != nil {
				reason += ": " + policyErr.Error()
			}
			return check(id, statusUnknown, reason), true
		}
		return PreflightCheck{}, false
	}

	return []PreflightCheck{
		checkBindingLifecycle(reg),
		checkBindingCompatibility(reg),
		checkBudget(spec, policy, policyUnknown),
		checkTimeout(spec, policy, policyUnknown),
		checkSandbox(spec, policy, policyUnknown),
		checkModelPolicyTask(spec, policy, policyUnknown),
		checkRefs(spec, policy, policyUnknown),
		checkApprovalGates(spec, policy, policyUnknown),
		checkCapabilityDiscovery(spec, specUnknown),
	}
}

func lifecycleStatus(kind, lc string) (status, detail string) {
	switch lc {
	case agentregistry.LifecyclePublished:
		return statusPass, kind + " " + lc
	case agentregistry.LifecycleDeprecated:
		return statusPass, kind + " " + lc + " (deprecated: still resolvable, but new bindings refuse it)"
	case agentregistry.LifecycleDisabled:
		return statusFail, kind + " " + lc
	case "":
		return statusUnknown, kind + " lifecycle not known"
	default:
		return statusUnknown, kind + " has unrecognised lifecycle " + fmt.Sprintf("%q", lc)
	}
}

func checkBindingLifecycle(reg *registryFacts) PreflightCheck {
	const id = "binding.lifecycle"
	if reg.err != nil {
		return check(id, statusUnknown, "registry read failed")
	}
	if reg.defLifecycle == "" && reg.profLifecycle == "" {
		return check(id, statusUnknown, "no registry row and no release-intent registryLifecycle")
	}
	ds, dd := lifecycleStatus("definition", reg.defLifecycle)
	ps, pd := lifecycleStatus("profile", reg.profLifecycle)
	status := statusPass
	switch {
	case ds == statusFail || ps == statusFail:
		status = statusFail
	case ds == statusUnknown || ps == statusUnknown:
		status = statusUnknown
	}
	detail := dd + "; " + pd
	if reg.fromFixture {
		detail += " (from a compatibility-fixture release intent, not the registry)"
	}
	return check(id, status, detail)
}

func checkBindingCompatibility(reg *registryFacts) PreflightCheck {
	const id = "binding.compatibility"
	if reg.err != nil {
		return check(id, statusUnknown, "registry read failed")
	}
	if reg.versionMismatch != "" {
		return check(id, statusUnknown, reg.versionMismatch)
	}
	if reg.compatSatisfied == nil {
		return check(id, statusUnknown, "nothing resolved from the registry")
	}
	if *reg.compatSatisfied {
		return check(id, statusPass, "profile satisfies definition range "+reg.compatRange)
	}
	return check(id, statusFail, "profile does not satisfy definition range "+reg.compatRange)
}

type unknownFn func(id string) (PreflightCheck, bool)

func checkBudget(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.budget"
	if c, ok := u(id); ok {
		return c
	}
	if spec.BudgetUsd == nil {
		return check(id, statusUnknown, "spec.budgetUsd absent")
	}
	if policy.Limits.MaxBudgetUsd == nil {
		return check(id, statusUnknown, "policy limits.maxBudgetUsd absent")
	}
	if *spec.BudgetUsd > *policy.Limits.MaxBudgetUsd {
		return check(id, statusFail, fmt.Sprintf("budgetUsd %v exceeds policy ceiling %v", *spec.BudgetUsd, *policy.Limits.MaxBudgetUsd))
	}
	return check(id, statusPass, fmt.Sprintf("budgetUsd %v within policy ceiling %v", *spec.BudgetUsd, *policy.Limits.MaxBudgetUsd))
}

func checkTimeout(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.timeout"
	if c, ok := u(id); ok {
		return c
	}
	if spec.TimeoutSeconds == nil {
		return check(id, statusUnknown, "spec.timeoutSeconds absent")
	}
	if policy.Limits.MaxTimeoutSeconds == nil {
		return check(id, statusUnknown, "policy limits.maxTimeoutSeconds absent")
	}
	if *spec.TimeoutSeconds > *policy.Limits.MaxTimeoutSeconds {
		return check(id, statusFail, fmt.Sprintf("timeoutSeconds %v exceeds policy ceiling %v", *spec.TimeoutSeconds, *policy.Limits.MaxTimeoutSeconds))
	}
	return check(id, statusPass, fmt.Sprintf("timeoutSeconds %v within policy ceiling %v", *spec.TimeoutSeconds, *policy.Limits.MaxTimeoutSeconds))
}

func checkSandbox(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.sandbox"
	if c, ok := u(id); ok {
		return c
	}
	sb := spec.Runtime.Sandbox
	if sb.Approved == nil {
		return check(id, statusUnknown, "spec.runtime.sandbox.approved absent")
	}
	if sb.Backend == "" || sb.ClusterWorkflowTemplate == "" {
		return check(id, statusUnknown, "spec.runtime.sandbox.backend or clusterWorkflowTemplate absent")
	}
	if !*sb.Approved {
		return check(id, statusFail, "runtime.sandbox.approved is false")
	}
	if !inList(policy.ApprovedSandboxes[sb.Backend], sb.ClusterWorkflowTemplate) {
		return check(id, statusFail, fmt.Sprintf("unapproved sandbox %s/%s (not in policy approvedSandboxes)", sb.Backend, sb.ClusterWorkflowTemplate))
	}
	return check(id, statusPass, fmt.Sprintf("sandbox %s/%s approved", sb.Backend, sb.ClusterWorkflowTemplate))
}

func checkModelPolicyTask(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.model_policy_task"
	if c, ok := u(id); ok {
		return c
	}
	task := spec.ModelPolicyRef.Task
	if task == "" {
		return check(id, statusUnknown, "spec.modelPolicyRef.task absent")
	}
	if !inList(policy.KnownModelPolicyTasks, task) {
		return check(id, statusFail, fmt.Sprintf("unknown modelPolicyRef.task %q", task))
	}
	return check(id, statusPass, fmt.Sprintf("modelPolicyRef.task %q is known", task))
}

func checkRefs(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.refs"
	if c, ok := u(id); ok {
		return c
	}
	var missing []string
	if spec.Tools == nil {
		missing = append(missing, "spec.tools")
	}
	if spec.Skills == nil {
		missing = append(missing, "spec.skills")
	}
	if spec.PolicyRef == "" {
		missing = append(missing, "spec.policyRef")
	}
	if spec.Evidence.Required == nil {
		missing = append(missing, "spec.evidence.required")
	}
	if len(missing) > 0 {
		return check(id, statusUnknown, "absent: "+strings.Join(missing, ", "))
	}
	var bad []string
	for _, t := range spec.Tools {
		if !inList(policy.KnownTools, t) {
			bad = append(bad, fmt.Sprintf("unknown tool %q", t))
		}
	}
	for _, s := range spec.Skills {
		if !inList(policy.KnownSkills, s) {
			bad = append(bad, fmt.Sprintf("unknown skill %q", s))
		}
	}
	if !inList(policy.KnownPolicies, spec.PolicyRef) {
		bad = append(bad, fmt.Sprintf("unknown policyRef %q", spec.PolicyRef))
	}
	for _, e := range spec.Evidence.Required {
		if !inList(policy.KnownEvidenceKinds, e) {
			bad = append(bad, fmt.Sprintf("unknown evidence kind %q", e))
		}
	}
	if len(bad) > 0 {
		return check(id, statusFail, strings.Join(bad, "; "))
	}
	return check(id, statusPass, "all tools, skills, policyRef and evidence kinds are known")
}

func checkApprovalGates(spec *gitops.ExecutionProfileSpec, policy *gitops.AgentPlatformPolicy, u unknownFn) PreflightCheck {
	const id = "profile.approval_gates"
	if c, ok := u(id); ok {
		return c
	}
	if spec.Approval.RequiredBefore == nil || spec.Permissions.MutationScopes == nil {
		return check(id, statusUnknown, "spec.approval.requiredBefore or spec.permissions.mutationScopes absent")
	}
	var bad []string
	for _, g := range spec.Approval.RequiredBefore {
		if !inList(policy.KnownApprovalGates, g) {
			bad = append(bad, fmt.Sprintf("unknown approval gate %q", g))
		}
	}
	scopes := map[string]gitops.MutationScope{}
	for _, s := range policy.KnownMutationScopes {
		scopes[s.Name] = s
	}
	for _, name := range spec.Permissions.MutationScopes {
		scope, ok := scopes[name]
		if !ok {
			bad = append(bad, fmt.Sprintf("unknown mutationScope %q", name))
			continue
		}
		if scope.Mutating && scope.RequiresApproval != "" && !inList(spec.Approval.RequiredBefore, scope.RequiresApproval) {
			bad = append(bad, fmt.Sprintf("mutationScope %q requires approval gate %q, absent from approval.requiredBefore", name, scope.RequiresApproval))
		}
	}
	if len(bad) > 0 {
		return check(id, statusFail, strings.Join(bad, "; "))
	}
	return check(id, statusPass, "approval gates and mutation scopes are known and covered")
}

func checkCapabilityDiscovery(spec *gitops.ExecutionProfileSpec, u func(string) (PreflightCheck, bool)) PreflightCheck {
	const id = "profile.capability_discovery"
	if c, ok := u(id); ok {
		return c
	}
	d := spec.CapabilityDiscovery
	if d == nil {
		return check(id, statusPass, "not declared")
	}
	if d.Enabled == nil {
		return check(id, statusUnknown, "spec.capabilityDiscovery.enabled absent")
	}
	var bad, incomplete []string
	aliases := map[string]bool{}
	ids := map[string]bool{}
	for i, p := range d.Providers {
		if p.Alias == "" || p.ID == "" || p.Type == "" {
			incomplete = append(incomplete, fmt.Sprintf("spec.capabilityDiscovery.providers[%d] needs type, id and alias", i))
			continue
		}
		if aliases[p.Alias] {
			bad = append(bad, fmt.Sprintf("providers[%d]: duplicate alias %q", i, p.Alias))
		}
		aliases[p.Alias] = true
		key := p.Type + "/" + p.ID
		if ids[key] {
			bad = append(bad, fmt.Sprintf("providers[%d]: duplicate provider %s", i, key))
		}
		ids[key] = true
		if p.ID == preflightMctlAPIProviderID && p.Alias != preflightMctlAPIAlias {
			bad = append(bad, fmt.Sprintf("providers[%d]: provider %q must use alias %q, got %q", i, preflightMctlAPIProviderID, preflightMctlAPIAlias, p.Alias))
		}
	}
	if *d.Enabled && !inList(spec.Tools, preflightMctlToolPattern) {
		bad = append(bad, "capabilityDiscovery.enabled is true but spec.tools does not declare "+preflightMctlToolPattern)
	}
	if len(bad) > 0 {
		return check(id, statusFail, strings.Join(bad, "; "))
	}
	if len(incomplete) > 0 {
		return check(id, statusUnknown, strings.Join(incomplete, "; "))
	}
	return check(id, statusPass, "capability discovery rules satisfied")
}

// verdict is fail if any check fails, else unknown if any is unknown (or
// there are no checks), else pass.
func verdict(checks []PreflightCheck) string {
	if len(checks) == 0 {
		return statusUnknown
	}
	out := statusPass
	for _, c := range checks {
		switch c.Status {
		case statusFail:
			return statusFail
		case statusPass:
		default:
			out = statusUnknown
		}
	}
	return out
}
