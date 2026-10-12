package telemetry

import "testing"

func TestValidTraceIDAndTraceparent(t *testing.T) {
	const id = "431486061c652efb376a860d9d656f25"
	if !ValidTraceID(id) {
		t.Fatal("valid id rejected")
	}
	for _, bad := range []string{"", id[:31], id + "0", "431486061C652EFB376A860D9D656F25", "zz1486061c652efb376a860d9d656f25", "00000000000000000000000000000000"} {
		if ValidTraceID(bad) {
			t.Errorf("ValidTraceID(%q) = true", bad)
		}
	}
	if got, ok := TraceIDFromTraceparent("00-" + id + "-7a16c732dc164e9e-01"); !ok || got != id {
		t.Errorf("valid traceparent: %q %v", got, ok)
	}
	for _, bad := range []string{"", "01-" + id + "-7a16c732dc164e9e-01", "00-00000000000000000000000000000000-7a16c732dc164e9e-01", "00-" + id + "-short-01"} {
		if _, ok := TraceIDFromTraceparent(bad); ok {
			t.Errorf("TraceIDFromTraceparent(%q) ok", bad)
		}
	}
}
