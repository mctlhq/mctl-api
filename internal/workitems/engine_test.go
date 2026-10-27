package workitems

import "testing"

// TestValidateEngine pins the engines an execution may name: the A2A engine
// joins Temporal and Argo, and anything else is still refused.
func TestValidateEngine(t *testing.T) {
	for _, e := range []string{EngineTemporal, EngineArgo, EngineA2A} {
		if err := validateEngine(e, "ref-1"); err != nil {
			t.Errorf("engine %q refused: %v", e, err)
		}
	}
	for _, e := range []string{"", "A2A", "mctl-support", "kubernetes"} {
		if err := validateEngine(e, "ref-1"); err == nil {
			t.Errorf("engine %q accepted", e)
		}
	}
	if err := validateEngine(EngineA2A, ""); err == nil {
		t.Error("an a2a execution without engine_ref was accepted")
	}
}
