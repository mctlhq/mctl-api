package deployplan

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// T7: deterministic, [a-z0-9]{6}, host shape.
func TestPreviewID(t *testing.T) {
	id := PreviewID("acme", "web", testRev, strings.Repeat("b", 40))
	if !regexp.MustCompile(`^[a-z0-9]{6}$`).MatchString(id) {
		t.Fatalf("id = %q", id)
	}
	if id != PreviewID("acme", "web", testRev, strings.Repeat("b", 40)) {
		t.Fatal("not deterministic")
	}
	for name, other := range map[string]string{
		"tenant":   PreviewID("acme2", "web", testRev, strings.Repeat("b", 40)),
		"service":  PreviewID("acme", "web2", testRev, strings.Repeat("b", 40)),
		"revision": PreviewID("acme", "web", strings.Repeat("c", 40), strings.Repeat("b", 40)),
		"base":     PreviewID("acme", "web", testRev, strings.Repeat("d", 40)),
	} {
		if other == id {
			t.Errorf("changing %s kept the id", name)
		}
	}
	if got := Host("web", id, "mctl.ai"); got != "web-"+id+".mctl.ai" {
		t.Errorf("host = %q", got)
	}
}

// T6: the converged fixture, plus a mutated matrix that must turn red.
func TestRequiredApproval(t *testing.T) {
	got := RequiredApproval(EnvironmentPreview, ActionUpdate)
	want := Approval{Required: true, Role: "owner", Reason: "preview_update_requires_approval_until_build_sandbox"}
	if got != want {
		t.Fatalf("approval = %+v, want %+v", got, want)
	}
	if a := RequiredApproval(EnvironmentPreview, ActionOnboard); !a.Required || a.Reason != "onboard_high_risk" {
		t.Fatalf("onboard approval = %+v", a)
	}
	if a := RequiredApproval("production", ActionUpdate); !a.Required {
		t.Fatal("an unplanned combination must fail closed to approval required")
	}
}

// The detector is real: a matrix that maps preview update to "no approval"
// is caught by the same assertion.
func TestPlanExpiredIsLazy(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := &Plan{ExpiresAt: now.Add(time.Minute)}
	if p.Expired(now) || !p.Expired(now.Add(time.Minute)) || !p.Expired(now.Add(time.Hour)) {
		t.Fatal("Expired boundary")
	}
}

func TestUnifiedDiff(t *testing.T) {
	if UnifiedDiff("a: 1\n", "a: 1\n") != "" {
		t.Fatal("equal inputs must give an empty diff")
	}
	d := UnifiedDiff("a: 1\nb: 2\nc: 3\n", "a: 1\nb: 5\nc: 3\nd: 4\n")
	for _, want := range []string{"--- before", "+++ after", "-b: 2", "+b: 5", "+d: 4", " a: 1", "@@ -1,3 +1,4 @@"} {
		if !strings.Contains(d, want) {
			t.Errorf("diff lacks %q:\n%s", want, d)
		}
	}
	if d != UnifiedDiff("a: 1\nb: 2\nc: 3\n", "a: 1\nb: 5\nc: 3\nd: 4\n") {
		t.Fatal("diff is not deterministic")
	}
}

func TestRedact(t *testing.T) {
	v := map[string]any{
		"externalSecret": map[string]any{
			"targetSecret": "web-secrets",
			"data":         []any{map[string]any{"secretKey": "A", "remoteKey": "teams/acme/web", "property": "p"}},
		},
		"extraExternalSecrets": map[string]any{"x": map[string]any{"data": []any{map[string]any{"remoteKey": "secret/data/platform/ghcr"}}}},
		"dbSecret":             map[string]any{"secretName": "db", "vaultPath": "secret/data/teams/acme/web/database"},
		"imagePullSecrets":     []any{map[string]any{"name": "ghcr-pull"}},
	}
	r := Redact(v)
	out, err := RenderYAML(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"teams/", "secret/data", "platform/ghcr"} {
		if strings.Contains(out, leak) {
			t.Errorf("redacted output leaks %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"redacted:sha256:" + SHA256Hex("teams/acme/web"), "web-secrets", "ghcr-pull", "secretKey: A"} {
		if !strings.Contains(out, keep) {
			t.Errorf("redacted output lacks %q:\n%s", keep, out)
		}
	}
	// The input is untouched.
	if v["externalSecret"].(map[string]any)["data"].([]any)[0].(map[string]any)["remoteKey"] != "teams/acme/web" {
		t.Fatal("Redact mutated its input")
	}
	// The digest still binds the real path.
	v2 := deepCopy(v).(map[string]any)
	v2["dbSecret"].(map[string]any)["vaultPath"] = "secret/data/teams/acme/web/other"
	a, _ := RenderYAML(Redact(v))
	b, _ := RenderYAML(Redact(v2))
	if a == b {
		t.Fatal("two different Vault paths redact to the same text")
	}
}
