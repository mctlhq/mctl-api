// Package governance is the authority and decision-context contract for
// action approvals (mctl-api#700, #182 F3/F4/F6/F9).
//
// It composes existing primitives and adds no authorization model: authority
// is still ADMIN_PRINCIPALS plus auth.HumanPrincipalChecker, and policy
// identity is still policy_rule_id/policy_version. What it adds is
//
//   - the decision context a reviewer must be shown (DecisionContextOf), and
//     a digest binding a decision to it (ContextDigest);
//   - the facts re-checked immediately before the side effect (Revalidate).
//
// Stored authority claims are evidence, never authorization.
package governance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Typed refusals. ErrContextIncomplete and ErrContextInvalid are refusals of
// the request as sent (no reapproval_required); ErrAuthorityUnavailable is a
// retryable fail-closed; every other one means the approval must be
// re-requested (reapproval_required).
var (
	ErrContextIncomplete    = errors.New("decision context is incomplete")
	ErrContextInvalid       = errors.New("decision context contradicts the platform's own classification")
	ErrContextChanged       = errors.New("decision context changed since it was approved")
	ErrApprovalStale        = workitems.ErrApprovalStale
	ErrAuthorityRevoked     = errors.New("the decider no longer holds approval authority")
	ErrDeciderDisabled      = errors.New("the decider's principal is no longer an active human")
	ErrAuthorityUnavailable = errors.New("the decider's authority could not be verified")
	ErrPolicyDrift          = errors.New("the policy version changed since the approval was decided")

	// ErrSpendContextIncomplete: an approved row whose mandatory context is
	// incomplete at spend time (e.g. a legacy row with no decided digest).
	// The approval must be re-requested.
	ErrSpendContextIncomplete = errors.New("approved decision context is incomplete")
	// ErrPolicyUnregistered: strict mode, the rule is not registered.
	ErrPolicyUnregistered = errors.New("the policy rule is not registered")
	// ErrPolicyUnavailable: strict mode, but no policy set is configured.
	ErrPolicyUnavailable = errors.New("the registered policy set is unavailable")
)

// AuthorityBasisPlatformAdmin is the basis recorded for a decision made by a
// human platform admin. Legacy rows read as AuthorityBasisUnrecorded.
const (
	AuthorityBasisPlatformAdmin = "platform_admin"
	AuthorityBasisUnrecorded    = "unrecorded"
)

// DefaultMaxDecisionAge is how long an approval stays spendable after it was
// decided, unless configured otherwise (ACTION_APPROVAL_MAX_DECISION_AGE).
const DefaultMaxDecisionAge = 24 * time.Hour

// DevLoopPolicyRule is the policy a DevLoop human approval is created under.
const DevLoopPolicyRule = "dev-loop.human-approval"

// Policy is the current registered version of a policy rule and the context
// defaults of an approval created under it.
type Policy struct {
	Version    string
	Decision   string   // "require_approval"
	Reasons    []string // reason codes
	SideEffect string   // none|read|write|destructive|external
}

// PolicySet maps a policy rule id to its current Policy.
type PolicySet map[string]Policy

// Policies is the registered policy set.
var Policies = PolicySet{
	DevLoopPolicyRule: {
		Version:    "v1",
		Decision:   "require_approval",
		Reasons:    []string{"dev-loop.proposal-acceptance"},
		SideEffect: "write",
	},
}

// Policy status values returned by Check.
const (
	PolicyOK           = "ok"
	PolicyUnregistered = "unregistered"
	PolicyDrift        = "drift"
)

// Admit is Check plus the strict-mode refusals: in strict mode an empty set
// is ErrPolicyUnavailable and an unregistered rule is ErrPolicyUnregistered.
// Drift is refused in either mode.
func (ps PolicySet) Admit(ruleID, version string, strict bool) (string, error) {
	if strict && len(ps) == 0 {
		return "", ErrPolicyUnavailable
	}
	status, err := ps.Check(ruleID, version)
	if err != nil {
		return PolicyDrift, err
	}
	if status == PolicyUnregistered && strict {
		return status, fmt.Errorf("%w: %q", ErrPolicyUnregistered, ruleID)
	}
	return status, nil
}

// SpendContextIncompleteError carries the missing fields of an approved row
// that is no longer (or never was) complete.
type SpendContextIncompleteError struct{ Missing []string }

func (e *SpendContextIncompleteError) Error() string {
	return ErrSpendContextIncomplete.Error() + ": missing " + strings.Join(e.Missing, ", ")
}

func (e *SpendContextIncompleteError) Unwrap() error { return ErrSpendContextIncomplete }

// Check compares an approval's policy version with the current one. An
// unregistered rule is reported, not refused; strict callers refuse it.
func (ps PolicySet) Check(ruleID, version string) (string, error) {
	p, ok := ps[ruleID]
	if !ok {
		return PolicyUnregistered, nil
	}
	if p.Version != version {
		return "", fmt.Errorf("%w: %s is at %s, approved under %s", ErrPolicyDrift, ruleID, p.Version, version)
	}
	return PolicyOK, nil
}

// PolicyRef is the policy part of a decision context.
type PolicyRef struct {
	RuleID   string   `json:"rule_id"`
	Version  string   `json:"version"`
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons"`
}

// DecisionContext is the read-side projection of an approval a reviewer is
// shown. It carries references, digests, enums and reason codes only: never
// args and never the free-text reason.
type DecisionContext struct {
	SchemaVersion string `json:"schema_version"`

	Target       string    `json:"target"`
	ArgsDigest   string    `json:"args_digest"`
	IntentHash   string    `json:"intent_hash"`
	ArtifactHash string    `json:"artifact_hash,omitempty"`
	RiskLevel    string    `json:"risk_level"`
	SideEffect   string    `json:"side_effect"`
	IntentSource string    `json:"intent_source"`
	ExecutionID  string    `json:"execution_id"`
	Policy       PolicyRef `json:"policy"`

	ActorKind              string `json:"actor_kind,omitempty"`
	ActorName              string `json:"actor_name,omitempty"`
	RequestedByPrincipalID string `json:"requested_by_principal_id,omitempty"`
	ViaPrincipalID         string `json:"via_principal_id,omitempty"`
	SubjectPrincipalID     string `json:"subject_principal_id,omitempty"`
	SubjectKind            string `json:"subject_kind,omitempty"`

	// Tenant is reserved: approvals carry no tenant yet (mctl-api#489).
	Tenant string `json:"tenant"`

	DecidedByPrincipalID  string `json:"decided_by_principal_id,omitempty"`
	DecidedViaPrincipalID string `json:"decided_via_principal_id,omitempty"`
	AuthorityBasis        string `json:"authority_basis"`
	AuthzMode             string `json:"authz_mode,omitempty"`

	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	FreshUntil *time.Time `json:"fresh_until,omitempty"`

	ContextDigest        string   `json:"context_digest"`
	DecidedContextDigest string   `json:"decided_context_digest,omitempty"`
	ContextComplete      bool     `json:"context_complete"`
	MissingFields        []string `json:"missing_fields"`
}

// DecisionContextSchemaVersion labels a DecisionContext.
const DecisionContextSchemaVersion = "decisioncontext/v1"

// Live is what the context is computed against: the registry that classifies
// risk. A registered action kind's risk is always the live registry value.
type Live struct {
	Registry *operations.Registry
}

// RiskOf is the risk level of an action kind: the registry's for a
// registered operation, otherwise the stored value.
func RiskOf(reg *operations.Registry, actionKind, stored string) string {
	if reg != nil {
		if op, ok := reg.Get(actionKind); ok {
			return string(op.RiskLevel)
		}
	}
	return stored
}

// DecisionContextOf projects an approval onto its decision context, with the
// exact list of mandatory fields that are empty.
func DecisionContextOf(a *workitems.ActionApprovalRequest, live Live) DecisionContext {
	reasons := a.PolicyReasons
	if reasons == nil {
		reasons = []string{}
	}
	basis := a.AuthorityBasis
	if basis == "" {
		basis = AuthorityBasisUnrecorded
	}
	c := DecisionContext{
		SchemaVersion: DecisionContextSchemaVersion,
		Target:        a.Target,
		ArgsDigest:    a.ArgsDigest,
		IntentHash:    a.IntentHash,
		ArtifactHash:  a.ArtifactHash,
		RiskLevel:     RiskOf(live.Registry, a.ActionKind, a.RiskLevel),
		SideEffect:    a.SideEffect,
		IntentSource:  a.IntentSource,
		ExecutionID:   a.ExecutionID,
		Policy: PolicyRef{
			RuleID: a.PolicyRuleID, Version: a.PolicyVersion, Decision: a.PolicyDecision, Reasons: reasons,
		},
		ActorKind:              a.ActorKind,
		ActorName:              a.ActorName,
		RequestedByPrincipalID: a.RequestedByPrincipalID,
		ViaPrincipalID:         a.ViaPrincipalID,
		SubjectPrincipalID:     a.SubjectPrincipalID,
		SubjectKind:            a.SubjectKind,
		DecidedByPrincipalID:   a.DecidedByPrincipalID,
		DecidedViaPrincipalID:  a.DecidedViaPrincipalID,
		AuthorityBasis:         basis,
		AuthzMode:              a.AuthzMode,
		CreatedAt:              a.CreatedAt,
		DecidedAt:              a.DecidedAt,
		ExpiresAt:              a.ExpiresAt,
		FreshUntil:             a.FreshUntil,
		DecidedContextDigest:   a.DecidedContextDigest,
		MissingFields:          []string{},
	}
	for _, f := range [][2]string{
		{"target", c.Target},
		{"args_digest", c.ArgsDigest},
		{"intent_hash", c.IntentHash},
		{"risk_level", c.RiskLevel},
		{"side_effect", c.SideEffect},
		{"intent_source", c.IntentSource},
		{"policy.rule_id", c.Policy.RuleID},
		{"policy.version", c.Policy.Version},
		{"policy.decision", c.Policy.Decision},
	} {
		if f[1] == "" {
			c.MissingFields = append(c.MissingFields, f[0])
		}
	}
	if len(c.Policy.Reasons) == 0 {
		c.MissingFields = append(c.MissingFields, "policy.reasons")
	}
	c.ContextComplete = len(c.MissingFields) == 0
	c.ContextDigest = ContextDigest(c)
	return c
}

const contextEncodingVersion = "mctl-decision-context/v1"

// ContextDigest is sha256 over the canonical encoding of the mandatory
// context:
//
//	mctl-decision-context/v1\n
//	<field>:<byte length>:<value>\n   (once per field, in this order)
//
// intent_hash, target, args_digest, artifact_hash, risk_level, side_effect,
// intent_source, policy_rule_id, policy_version, policy_decision,
// policy_reasons (joined by ","). Same length-prefixed style as the action
// intent hash, so any client reproduces it. Result: "sha256:<hex>".
func ContextDigest(c DecisionContext) string {
	var b strings.Builder
	b.WriteString(contextEncodingVersion)
	b.WriteByte('\n')
	for _, f := range [][2]string{
		{"intent_hash", c.IntentHash},
		{"target", c.Target},
		{"args_digest", c.ArgsDigest},
		{"artifact_hash", c.ArtifactHash},
		{"risk_level", c.RiskLevel},
		{"side_effect", c.SideEffect},
		{"intent_source", c.IntentSource},
		{"policy_rule_id", c.Policy.RuleID},
		{"policy_version", c.Policy.Version},
		{"policy_decision", c.Policy.Decision},
		{"policy_reasons", strings.Join(c.Policy.Reasons, ",")},
	} {
		b.WriteString(f[0])
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(f[1])))
		b.WriteByte(':')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CreateContext is the client-suppliable part of the context.
type CreateContext struct {
	RiskLevel      string
	SideEffect     string
	IntentSource   string
	PolicyDecision string
	PolicyReasons  []string
}

// Missing names the fields an approve requires that c still lacks, in the
// decision context's own names. A request created without them could never
// be approved, so create refuses it. intent_source is not checked: it is
// derived from the execution id, whose absence the store refuses as invalid.
func (c CreateContext) Missing() []string {
	var missing []string
	for _, f := range [][2]string{
		{"risk_level", c.RiskLevel},
		{"side_effect", c.SideEffect},
		{"policy.decision", c.PolicyDecision},
	} {
		if f[1] == "" {
			missing = append(missing, f[0])
		}
	}
	if len(c.PolicyReasons) == 0 {
		missing = append(missing, "policy.reasons")
	}
	return missing
}

// FillCreateContext completes a requested context at create time. The risk of
// a registered action kind is the registry's: a contradicting client value is
// ErrContextInvalid, so a client cannot downgrade a known operation. Omitted
// fields are filled from the registered policy and, for intent_source, from
// the work item or execution the intent names.
func FillCreateContext(c CreateContext, intent workitems.ActionIntent, reg *operations.Registry, ps PolicySet) (CreateContext, error) {
	if reg != nil {
		if op, ok := reg.Get(intent.ActionKind); ok {
			if c.RiskLevel != "" && c.RiskLevel != string(op.RiskLevel) {
				return c, fmt.Errorf("%w: %s is %s, request says %s", ErrContextInvalid, intent.ActionKind, op.RiskLevel, c.RiskLevel)
			}
			c.RiskLevel = string(op.RiskLevel)
		}
	}
	if p, ok := ps[intent.PolicyRuleID]; ok {
		if c.SideEffect == "" {
			c.SideEffect = p.SideEffect
		}
		if c.PolicyDecision == "" {
			c.PolicyDecision = p.Decision
		}
		if len(c.PolicyReasons) == 0 {
			c.PolicyReasons = append([]string(nil), p.Reasons...)
		}
	}
	if c.IntentSource == "" {
		switch {
		case intent.WorkItemID != "":
			c.IntentSource = "work_item:" + intent.WorkItemID
		case intent.ExecutionID != "":
			c.IntentSource = "execution:" + intent.ExecutionID
		}
	}
	return c, nil
}

// LiveAuthority is everything Revalidate re-reads at spend time.
type LiveAuthority struct {
	// PrincipalMode: TENANT_AUTHZ_MODE=principal, where ADMIN_PRINCIPALS is
	// the platform admin set. In other modes admin membership is skipped.
	PrincipalMode bool
	Mode          string
	Admins        map[string]bool
	// Checker is the principal resolver; asserted to HumanPrincipalChecker.
	Checker  auth.PrincipalResolver
	Policies PolicySet
	// StrictPolicy refuses a rule that is not registered.
	StrictPolicy bool
	Registry     *operations.Registry
	Now          time.Time
}

// Result records what Revalidate established, for the audit.
type Result struct {
	Revalidation string // "ok" | "skipped_legacy_mode"
	PolicyStatus string // "ok" | "unregistered"
}

// Revalidate re-checks, in order and failing on the first, the facts an
// approval's side effect depends on: the context, the decision's freshness,
// the decider's current authority and the policy version.
func Revalidate(ctx context.Context, a *workitems.ActionApprovalRequest, live LiveAuthority) (Result, error) {
	res := Result{Revalidation: "ok"}

	// Step 0: an approved row must be complete when spent, including a
	// legacy row that has no decided digest to compare against.
	if c := DecisionContextOf(a, Live{Registry: live.Registry}); !c.ContextComplete {
		return res, &SpendContextIncompleteError{Missing: c.MissingFields}
	}

	// F6: the context the reviewer approved is the context being spent.
	if a.DecidedContextDigest != "" {
		if cur := DecisionContextOf(a, Live{Registry: live.Registry}); cur.ContextDigest != a.DecidedContextDigest {
			return res, fmt.Errorf("%w: %s", ErrContextChanged, a.ID)
		}
	}

	// F4: freshness. expires_at stays with the store's CAS.
	if a.FreshUntil != nil && !a.FreshUntil.After(live.Now) {
		return res, fmt.Errorf("%w: %s was fresh until %s", ErrApprovalStale, a.ID, a.FreshUntil.Format(time.RFC3339))
	}

	// F3: the decider still holds authority.
	prn := a.DecidedByPrincipalID
	switch {
	case prn == "" && live.PrincipalMode:
		return res, fmt.Errorf("%w: %s records no decider principal", ErrAuthorityRevoked, a.ID)
	case prn == "":
		// Legacy authz decides admins by login, not principal: a decision
		// made then has none to re-check.
		res.Revalidation = "skipped_legacy_mode"
	default:
		checker, ok := live.Checker.(auth.HumanPrincipalChecker)
		if !ok {
			return res, fmt.Errorf("%w: the principal store cannot check a principal's kind", ErrAuthorityUnavailable)
		}
		switch err := checker.CheckHumanPrincipal(ctx, prn); {
		case err == nil:
		case errors.Is(err, auth.ErrPrincipalDisabled), errors.Is(err, auth.ErrIdentityRefused):
			return res, fmt.Errorf("%w: %s", ErrDeciderDisabled, a.ID)
		default:
			return res, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
		}
		if live.PrincipalMode {
			if !live.Admins[prn] {
				return res, fmt.Errorf("%w: %s", ErrAuthorityRevoked, a.ID)
			}
		} else {
			res.Revalidation = "skipped_legacy_mode"
		}
	}

	// F9: the policy has not moved on.
	status, err := live.Policies.Admit(a.PolicyRuleID, a.PolicyVersion, live.StrictPolicy)
	res.PolicyStatus = status
	if err != nil {
		return res, err
	}
	return res, nil
}
