package reviewreceipts

import (
	"fmt"
	"strings"
)

// EvaluateReviewGate answers whether the live subject has a current,
// independent review. It is a pure port of Tier A evaluate_review_gate.
//
// live is the subject as the caller just observed it (nil when it could not
// be observed). request carries the authoring facts for that live revision
// (nil when unavailable). pool is the complete candidate pool in ingest
// order, oldest first. requiredAssurance is "independent" or "any"; any other
// value is an error.
func EvaluateReviewGate(live *ReviewSubject, request *ReviewRequest, pool []ReviewReceipt, requiredAssurance string) (string, error) {
	if requiredAssurance != AssuranceIndependent && requiredAssurance != AssuranceAny {
		return "", fmt.Errorf("required_assurance must be one of [%s %s]", AssuranceIndependent, AssuranceAny)
	}
	if live == nil {
		return GateUnknown, nil
	}
	var same, bound []ReviewReceipt
	for i := range pool {
		if pool[i].Subject.Identity() == live.Identity() {
			same = append(same, pool[i])
		}
	}
	for i := range same {
		if same[i].Subject.Binding() == live.Binding() {
			bound = append(bound, same[i])
		}
	}
	if len(bound) == 0 {
		if len(same) > 0 {
			return GateStale, nil
		}
		return GateMissing, nil
	}
	// The authoring facts must describe this exact revision.
	if request == nil || request.Subject.Binding() != live.Binding() || request.RequestID == "" {
		return GateUnknown, nil
	}
	if request.Mode == ModeWorker && request.AuthoringExecutionID == "" {
		return GateUnknown, nil
	}
	var own []ReviewReceipt
	for i := range bound {
		if bound[i].RequestID == request.RequestID {
			own = append(own, bound[i])
		}
	}
	if len(own) == 0 {
		return GateMissing, nil
	}
	authors := map[string]struct{}{}
	for _, a := range request.AuthorActors {
		authors[strings.ToLower(a)] = struct{}{}
	}
	attempts := map[string]struct{}{}
	for _, a := range request.AuthoringAttemptIDs {
		attempts[a] = struct{}{}
	}
	independent := func(r ReviewReceipt) bool {
		if r.ReviewerActor == "" {
			return false
		}
		if _, isAuthor := authors[strings.ToLower(r.ReviewerActor)]; isAuthor {
			return false
		}
		// A worker receipt that cannot name its execution, attempt and
		// lineage cannot be compared with the author's.
		if r.Mode == ModeWorker && (r.ReviewerExecutionID == "" || r.AttemptID == "" || r.LineageRoot == "") {
			return false
		}
		if request.AuthoringExecutionID != "" && r.ReviewerExecutionID == request.AuthoringExecutionID {
			return false
		}
		if _, same := attempts[r.AttemptID]; r.AttemptID != "" && same {
			return false
		}
		return request.AuthoringLineageRoot == "" || r.LineageRoot != request.AuthoringLineageRoot
	}
	var indep []ReviewReceipt
	for _, r := range own {
		if independent(r) {
			indep = append(indep, r)
		}
	}
	if len(indep) == 0 {
		return GateNotIndependent, nil
	}
	if requiredAssurance == AssuranceIndependent {
		var assured []ReviewReceipt
		for _, r := range indep {
			if r.Assurance == AssuranceIndependent {
				assured = append(assured, r)
			}
		}
		if len(assured) == 0 {
			return GateAdvisoryOnly, nil
		}
		indep = assured
	}
	// A receipt not built by ParseReceipt/SealReceipt may carry an unknown
	// outcome; that is unknown, never a silent empty verdict.
	verdict, ok := outcomeToGate[indep[len(indep)-1].Outcome]
	if !ok {
		return GateUnknown, nil
	}
	return verdict, nil
}
