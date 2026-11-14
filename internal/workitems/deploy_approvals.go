package workitems

import (
	"context"
	"fmt"
	"strings"
)

// Deploy grants (mctl-api#1026, mctlhq/.github#254 item 4).
//
// A deploy.apply approval is a human grant for one stored deploy plan
// (internal/deployplan): its intent binds the plan id, the plan digest, the
// tenant/service target and the deploy policy, and is built by the server
// from the stored plan, never from a request body. It is spent once, by the
// apply route, right before preview-deploy is submitted.
//
// Like the Glovo kinds, deploy kinds live in their own namespace that every
// generic route refuses: they are created, decided and consumed only through
// the methods below. The reason is the decider. The person who approves is a
// live owner of the plan's tenant, and an MCP session of that same person
// carries the same principal as their browser, so "the requester may not
// decide" cannot tell the agent from its owner (owner decision 2026-11-14,
// mctl-api#1026). What tells them apart is presence: the decision is made
// only on a page that demands a fresh interactive sign-in, which a bearer
// token cannot provide. DecideDeployApproval therefore does not refuse the
// requester's own principal, and nothing but that page may call it.

const (
	// ActionKindDeployApply is the grant of one preview apply of one plan.
	ActionKindDeployApply = "deploy.apply"

	// deployKindPrefix is the namespace of deploy kinds.
	deployKindPrefix = "deploy."

	// DeployApplyPolicyRuleID and DeployApplyPolicyVersion are the policy a
	// deploy.apply grant is created under (governance.Policies).
	DeployApplyPolicyRuleID  = "deploy.apply.tenant-owner"
	DeployApplyPolicyVersion = "1"

	// DeployAuthorityBasis is what a deploy decision records: a live owner of
	// the plan's tenant, signed in fresh. Spending re-checks the ownership.
	DeployAuthorityBasis = "tenant_owner_fresh_login"

	// deployIdempotencyPrefix scopes the UNIQUE (requested_by,
	// idempotency_key) to one plan: one grant request per plan and requester.
	deployIdempotencyPrefix = "deploy-plan:"
)

// IsDeployKind reports whether kind is in the deploy namespace. As with
// IsGlovoKind the prefix is the predicate: "deploy.other" is refused by the
// generic paths too.
func IsDeployKind(kind string) bool { return strings.HasPrefix(kind, deployKindPrefix) }

// isDedicatedKind is a kind that only its own paths create, decide or spend.
func isDedicatedKind(kind string) bool { return IsGlovoKind(kind) || IsDeployKind(kind) }

// dedicatedKindPredicate is isDedicatedKind in SQL, parenthesized so it can be
// negated as it stands.
const dedicatedKindPredicate = `(action_kind LIKE 'glovo.%' OR action_kind LIKE 'deploy.%')`

// DeployIdempotencyKey is the idempotency key of the grant request for a plan.
func DeployIdempotencyKey(planID string) string { return deployIdempotencyPrefix + planID }

// CreateDeployApproval stores the pending deploy.apply request for a plan, or
// returns the one this requester already holds for it (created=false). The
// caller builds in from the stored plan; anything else is refused.
func (s *Store) CreateDeployApproval(ctx context.Context, in ActionApprovalInput) (*ActionApprovalRequest, bool, error) {
	switch {
	case in.ActionKind != ActionKindDeployApply:
		return nil, false, invalid("a deploy approval must be of kind %s", ActionKindDeployApply)
	case in.PolicyRuleID != DeployApplyPolicyRuleID || in.PolicyVersion != DeployApplyPolicyVersion:
		return nil, false, invalid("a deploy approval is created under %s version %s", DeployApplyPolicyRuleID, DeployApplyPolicyVersion)
	case in.IdempotencyKey != DeployIdempotencyKey(in.ExecutionID):
		return nil, false, invalid("a deploy approval's idempotency key is derived from its plan")
	case in.WorkItemID != "":
		return nil, false, invalid("a deploy approval names no work item")
	}
	return s.createActionApproval(ctx, in)
}

// DecideDeployApproval decides a pending deploy.apply request. It records the
// decider and DeployAuthorityBasis, and unlike DecideActionApproval it does
// not refuse a decider whose principal requested the grant (see the package
// comment above): the only caller is the fresh-sign-in decide page, which has
// verified that the decider is a live owner of the plan's tenant. A decider
// with no principal is refused, because ownership is re-checked by principal
// when the grant is spent.
func (s *Store) DecideDeployApproval(ctx context.Context, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if in.DecidedByPrincipalID == "" {
		return nil, fmt.Errorf("%w: %s", ErrApprovalDeciderUnresolved, in.ID)
	}
	if in.Decision == DecisionApprove {
		in.AuthorityBasis = DeployAuthorityBasis
	}
	return s.decideActionApproval(ctx, in, true)
}

// ConsumeDeployApproval spends an approved deploy.apply request: the same
// compare-and-set as ConsumeActionApproval, held to the deploy kind.
func (s *Store) ConsumeDeployApproval(ctx context.Context, id, intentHash string) (*ActionApprovalRequest, error) {
	return s.consumeActionApproval(ctx, id, intentHash, true)
}
