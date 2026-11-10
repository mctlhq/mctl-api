package receipt

import (
	"context"
	"errors"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Reasons Ready reports; every one is a not_ready.
const (
	NotReadyGlovoURL       = "glovo_db_url_not_explicit"
	NotReadyWorkItemsURL   = "work_items_db_url_not_explicit"
	NotReadyGlovoStore     = "glovo_store_not_ready"
	NotReadyOneDatabase    = "one_database_not_proven"
	NotReadySchema         = "approval_schema_not_ready"
	NotReadyPolicy         = "policy_not_registered"
	NotReadyCollaborator   = "collaborator_missing"
	NotReadyBasketContract = "basket_contract_missing"
	NotReadyWireVersions   = "wire_versions_disabled"
	NotReadyAudit          = "joint_state_violation"
)

// Deps is everything Ready needs. Nothing in it is read from the environment
// here: the caller states what it wired.
type Deps struct {
	// GlovoURLExplicit and WorkItemsURLExplicit are true only when
	// GLOVO_DB_URL and WORK_ITEMS_DB_URL were each set explicitly, with no
	// AUDIT_DB_URL fallback.
	GlovoURLExplicit, WorkItemsURLExplicit bool
	// GlovoStoreReady is glovo.Store.Ready: the runtime role is
	// glovo_runtime, owns nothing and holds exactly the registered grants.
	GlovoStoreReady func(ctx context.Context) error
	// ProveOneDatabase is the #985 control.ProveOneDatabase result, injected so
	// that no #989 package imports #985's.
	ProveOneDatabase func(ctx context.Context) error
	// Glovo is the Glovo pool (glovo_runtime), for the approval schema proof.
	Glovo dbq.Querier
	// Audit is a pool that reads the approval tables, schema glovo and the
	// bridge tables, for the joint-state table.
	Audit dbq.Querier
	// Policies is the registered policy set.
	Policies governance.PolicySet
	// Collaborators: the work-items, bridge, #988 order and #959 connection
	// stores and the membership reader. Every one is required.
	WorkItems, Bridge, Orders, Conns, Members any
	// WireVersionsEnabled is bridge.Store.WireVersionsEnabled (#986).
	WireVersionsEnabled func() bool
}

func notReady(reason string, cause error) error {
	return &glovo.NotReadyError{Reason: reason, Cause: cause}
}

// Ready is nil only when every condition of design section 8 holds. A check
// that could not run is not_ready, never a pass; the first failing condition
// is reported. Only #985 task 9 installs the fence, and only after a nil
// Ready.
func Ready(ctx context.Context, d Deps) error {
	if !d.GlovoURLExplicit {
		return notReady(NotReadyGlovoURL, nil)
	}
	if !d.WorkItemsURLExplicit {
		return notReady(NotReadyWorkItemsURL, nil)
	}
	for _, c := range []any{d.WorkItems, d.Bridge, d.Orders, d.Conns, d.Members} {
		if isNil(c) {
			return notReady(NotReadyCollaborator, nil)
		}
	}
	if d.GlovoStoreReady == nil || d.ProveOneDatabase == nil || isNil(d.Glovo) || isNil(d.Audit) || d.WireVersionsEnabled == nil {
		return notReady(NotReadyCollaborator, nil)
	}
	if err := d.GlovoStoreReady(ctx); err != nil {
		return notReady(NotReadyGlovoStore, err)
	}
	if err := d.ProveOneDatabase(ctx); err != nil {
		return notReady(NotReadyOneDatabase, err)
	}
	if err := workitems.VerifyGlovoApprovalSchema(ctx, d.Glovo); err != nil {
		return notReady(NotReadySchema, err)
	}
	if _, err := d.Policies.Admit(workitems.GlovoPolicyRuleID, workitems.GlovoPolicyVersion, true); err != nil {
		return notReady(NotReadyPolicy, err)
	}
	// The #1059 approval basket (vendored by #988) must compile and answer: an
	// empty object is a typed refusal, never a compile or I/O error.
	if _, _, err := basket.Parse([]byte(`{}`)); err == nil || !errors.Is(err, basket.ErrInvalid) {
		return notReady(NotReadyBasketContract, err)
	}
	if !d.WireVersionsEnabled() {
		return notReady(NotReadyWireVersions, nil)
	}
	res, err := Audit(ctx, d.Audit)
	if err != nil {
		return notReady(NotReadyAudit, err)
	}
	if len(res.Violations) > 0 {
		return notReady(NotReadyAudit, nil)
	}
	return nil
}
