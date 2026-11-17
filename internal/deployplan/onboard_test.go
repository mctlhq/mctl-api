package deployplan

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

const onboardExtra = `,"env":{"FEATURE":"on"},"secretRefs":[{"env":"DB_PASSWORD","property":"password"}]`

func onboardPlan(t *testing.T) (*Plan, Intent) {
	t.Helper()
	in, canon := mustParse(t, testIntentJSON("acme", "web", onboardExtra))
	id := PreviewID("acme", "web", in.Spec.Source.Revision, strings.Repeat("b", 40))
	host := Host("web", id, "mctl.ai")
	_, after, err := CompileOnboardPreview(in, "mctlhq", id, host)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RenderYAML(Redact(after))
	if err != nil {
		t.Fatal(err)
	}
	return &Plan{
		Tenant: "acme", Service: "web", Environment: EnvironmentPreview, Action: ActionOnboard,
		IntentCanonical: string(canon), PreviewID: id, Host: host, ValuesAfter: redacted,
	}, in
}

func decodeCompiled(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The platform base names the built image and the pull secret; the intent
// adds only what the schema allows; the compiled values are the real ones
// (Vault paths included, rewritten to preview/) while the plan stores the
// redacted rendering.
func TestOnboardValuesForPlan(t *testing.T) {
	p, in := onboardPlan(t)
	b64, sha, err := OnboardValuesForPlan(p, in, "mctlhq")
	if err != nil {
		t.Fatal(err)
	}
	got := decodeCompiled(t, b64)
	if SHA256Hex(got) != sha {
		t.Fatalf("sha %s is not the hash of the decoded values", sha)
	}
	for _, want := range []string{
		"repository: ghcr.io/mctlhq/web", "name: ghcr-credentials", "port: 8080",
		"remoteKey: teams/acme/web/preview", "mctl.ai/preview-id: " + p.PreviewID,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("compiled values lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(p.ValuesAfter, "teams/acme/web") || !strings.Contains(p.ValuesAfter, "redacted:sha256:") {
		t.Errorf("the stored rendering is not redacted:\n%s", p.ValuesAfter)
	}
}

// What is deployed is what was approved: values that no longer render to the
// plan's ValuesAfter are refused, whatever changed them.
func TestOnboardValuesForPlan_RefusesValuesThatDiffer(t *testing.T) {
	p, in := onboardPlan(t)
	p.ValuesAfter = strings.Replace(p.ValuesAfter, "port: 8080", "port: 9090", 1)
	if _, _, err := OnboardValuesForPlan(p, in, "mctlhq"); !errors.Is(err, ErrOnboardNotReproducible) {
		t.Fatalf("err = %v, want ErrOnboardNotReproducible", err)
	}
	// A different image organization is a different rendering too.
	p2, in2 := onboardPlan(t)
	if _, _, err := OnboardValuesForPlan(p2, in2, "someone-else"); !errors.Is(err, ErrOnboardNotReproducible) {
		t.Fatalf("other org: err = %v", err)
	}
}

func TestOnboardBase_RefusesAnImageRepositoryThatIsNotOne(t *testing.T) {
	for _, org := range []string{"", "Up", "a/b", "a b", "-x"} {
		if _, _, err := OnboardBase("web", org); err == nil {
			t.Errorf("org %q accepted", org)
		}
	}
	if _, _, err := OnboardBase("web", "mctlhq"); err != nil {
		t.Fatal(err)
	}
}

func TestCompiledValues_RefusesOversizedValues(t *testing.T) {
	// Incompressible content, so the cap is reached.
	buf := make([]byte, 120000)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	big := map[string]any{"env": map[string]any{"BLOB": base64.StdEncoding.EncodeToString(buf)}}
	if _, _, err := CompiledValues(big); !errors.Is(err, ErrOnboardNotReproducible) {
		t.Fatalf("oversized values: err = %v", err)
	}
	if _, _, err := CompiledValues(map[string]any{"env": map[string]any{"A": "b"}}); err != nil {
		t.Fatal(err)
	}
}
