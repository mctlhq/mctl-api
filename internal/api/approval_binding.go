package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
	"net/http"
)

// Binding of a direct human decision to the exact grant and context the
// person was shown (mctl-api#869 slice 1; docs/decision-context-contract.md).

// ApprovalBindingMode is the parsed MCTL_APPROVAL_BINDING.
type ApprovalBindingMode string

const (
	ApprovalBindingOff     ApprovalBindingMode = "off"
	ApprovalBindingObserve ApprovalBindingMode = "observe"
	ApprovalBindingEnforce ApprovalBindingMode = "enforce"
)

// ParseApprovalBindingMode reads MCTL_APPROVAL_BINDING. Empty is observe. An
// unknown value is refused so a mistyped mode stops the boot.
func ParseApprovalBindingMode(raw string) (ApprovalBindingMode, error) {
	switch m := ApprovalBindingMode(strings.TrimSpace(raw)); m {
	case "":
		return ApprovalBindingObserve, nil
	case ApprovalBindingOff, ApprovalBindingObserve, ApprovalBindingEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("MCTL_APPROVAL_BINDING %q is not one of off, observe, enforce", raw)
	}
}

const aarCodeBindingMissing = "approval_binding_missing"

// errBindingMissing is the 422 of an absent (enforce) or partial binding.
var errBindingMissing = errors.New("the decision binding is missing or incomplete")

// bindingMissingError carries the missing or malformed fields.
type bindingMissingError struct{ missing []string }

func (e *bindingMissingError) Error() string {
	return errBindingMissing.Error() + ": " + strings.Join(e.missing, ", ")
}
func (e *bindingMissingError) Unwrap() error { return errBindingMissing }

// decisionBinding is what the person was shown: the aar_ id, the
// decision_context.context_digest and the artifact_hash (proposal content
// digest) of that grant at render time.
type decisionBinding struct {
	ApprovalRef   string `json:"approval_ref"`
	ContextDigest string `json:"context_digest"`
	ContentDigest string `json:"content_digest"`
}

const maxBindingFieldBytes = 256

func wellFormedBindingValue(s string) bool {
	return s != "" && len(s) <= maxBindingFieldBytes && strings.TrimSpace(s) == s && !strings.ContainsAny(s, " \t\r\n")
}

// missingFields lists every field that is absent or malformed. A nil
// binding misses all three.
func (b *decisionBinding) missingFields() []string {
	var out []string
	if b == nil {
		return []string{"approval_ref", "context_digest", "content_digest"}
	}
	if !wellFormedBindingValue(b.ApprovalRef) || !strings.HasPrefix(b.ApprovalRef, "aar_") {
		out = append(out, "approval_ref")
	}
	if !wellFormedBindingValue(b.ContextDigest) {
		out = append(out, "context_digest")
	}
	if !wellFormedBindingValue(b.ContentDigest) {
		out = append(out, "content_digest")
	}
	return out
}

func (h *Handlers) approvalBindingMode() ApprovalBindingMode {
	// The zero value is off; cmd/api always sets the parsed mode, whose
	// default is observe.
	if h.opts.ApprovalBindingMode == "" {
		return ApprovalBindingOff
	}
	return h.opts.ApprovalBindingMode
}

// approvalBindingAbsentTotal counts decisions accepted without a binding in
// observe mode, per route: the evidence for the enforce flip.
var approvalBindingAbsentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "approval_binding_absent_total",
	Help: "Direct human decisions accepted without a binding in observe mode (mctl-api#869), by route.",
}, []string{"route"})

func init() { prometheus.MustRegister(approvalBindingAbsentTotal) }

const (
	bindingRouteActionApproval = "action_approval"
	bindingRouteDevLoop        = "dev_loop"
)

// bindingGate applies the shape rule and the server mode. It returns the
// fields to refuse with (nil: go on). An absent binding in observe mode is
// audited and counted here.
func (h *Handlers) bindingGate(r *http.Request, user *auth.User, route, id string, b *decisionBinding) []string {
	if b != nil {
		return b.missingFields()
	}
	switch h.approvalBindingMode() {
	case ApprovalBindingEnforce:
		return b.missingFields()
	case ApprovalBindingObserve:
		approvalBindingAbsentTotal.WithLabelValues(route).Inc()
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "approval.binding_absent",
			Parameters: map[string]string{"route": route, "approval_id": id, "actor": principalOf(user)},
			Status:     "succeeded",
			RiskLevel:  string(operations.RiskMedium),
		})
	}
	return nil
}

// bindingMatches compares what the person saw with what the grant holds.
func bindingMatches(b *decisionBinding, a *workitems.ActionApprovalRequest, contextDigest string) bool {
	return b.ApprovalRef == a.ID && b.ContextDigest == contextDigest && b.ContentDigest == a.ArtifactHash
}
