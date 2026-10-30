package deployplan

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const goldenDir = "testdata/golden"

type goldenCase struct {
	Tenant    string          `json:"tenant"`
	Service   string          `json:"service"`
	Revision  string          `json:"revision"`
	PreviewID string          `json:"preview_id"`
	Host      string          `json:"host"`
	Intent    json.RawMessage `json:"intent"`
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// yamlAsJSON normalizes a YAML document to the same shape the compiler
// produces, so the comparison ignores formatting.
func yamlAsJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	n, err := normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	return n.(map[string]any)
}

// T5: the compiler against values captured from the real rewrite script and
// the --set list of the real workflow template (testdata/upstream).
func TestGoldenCompile(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "*", "case.json"))
	if err != nil || len(dirs) < 4 {
		t.Fatalf("golden cases: %v %v", dirs, err)
	}
	for _, caseFile := range dirs {
		dir := filepath.Dir(caseFile)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			var c goldenCase
			if err := json.Unmarshal(readFile(t, caseFile), &c); err != nil {
				t.Fatal(err)
			}
			in, _ := mustParse(t, c.Intent)
			if in.Metadata.Tenant != c.Tenant || in.Metadata.Service != c.Service || in.Spec.Source.Revision != c.Revision {
				t.Fatal("case.json disagrees with its intent")
			}
			base := readFile(t, filepath.Join(dir, "base.yaml"))
			before, after, err := CompilePreview(base, in, c.PreviewID, c.Host)
			if _, statErr := os.Stat(filepath.Join(dir, "expected-refused.txt")); statErr == nil {
				if !errors.Is(err, ErrPreviewValuesRefused) {
					t.Fatalf("want ErrPreviewValuesRefused (the script exits non-zero), got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantBefore := yamlAsJSON(t, readFile(t, filepath.Join(dir, "expected-before.yaml")))
			wantAfter := yamlAsJSON(t, readFile(t, filepath.Join(dir, "expected-after.yaml")))
			if !reflect.DeepEqual(yamlAsJSON(t, mustYAML(t, before)), wantBefore) {
				t.Errorf("before differs:\n%s\nwant:\n%s", mustYAML(t, before), readFile(t, filepath.Join(dir, "expected-before.yaml")))
			}
			if !reflect.DeepEqual(yamlAsJSON(t, mustYAML(t, after)), wantAfter) {
				t.Errorf("after differs:\n%s\nwant:\n%s", mustYAML(t, after), readFile(t, filepath.Join(dir, "expected-after.yaml")))
			}
		})
	}
}

func mustYAML(t *testing.T, v map[string]any) []byte {
	t.Helper()
	s, err := RenderYAML(v)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

// The golden values were captured from the snapshots that are pinned now.
func TestGoldenCapturedFromPinnedSnapshots(t *testing.T) {
	var cap struct {
		SourceCommit string `json:"source_commit"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(goldenDir, "captured-from.json")), &cap); err != nil {
		t.Fatal(err)
	}
	prov := loadUpstreamProvenance(t)
	if cap.SourceCommit == "" || cap.SourceCommit != prov.SourceCommit {
		t.Fatalf("golden fixtures were captured from %q but the snapshots are pinned at %q: rerun testdata/golden/capture.py",
			cap.SourceCommit, prov.SourceCommit)
	}
}

func TestCompilePreview_UnparseableBase(t *testing.T) {
	in, _ := mustParse(t, testIntentJSON("acme", "web", ""))
	for name, base := range map[string]string{
		"a list":        "- a\n- b\n",
		"a scalar":      "just text\n",
		"yaml error":    "a: [1\n",
		"non-str keys":  "1: a\n",
		"nested badkey": "a:\n  1: x\n",
	} {
		_, _, err := CompilePreview([]byte(base), in, "abc123", "web-abc123.mctl.ai")
		if !errors.Is(err, ErrValuesUnparseable) {
			t.Errorf("%s: err = %v, want ErrValuesUnparseable", name, err)
		}
	}
}

// The compile is deterministic and leaves the base alone.
func TestCompilePreview_Deterministic(t *testing.T) {
	in, _ := mustParse(t, testIntentJSON("acme", "web", `,"env":{"A":"1","B":"2","C":"3"}`))
	base := readFile(t, filepath.Join(goldenDir, "basic-team-secrets", "base.yaml"))
	var first string
	for i := 0; i < 5; i++ {
		_, after, err := CompilePreview(base, in, "abc123", "web-abc123.mctl.ai")
		if err != nil {
			t.Fatal(err)
		}
		out := string(mustYAML(t, after))
		if i == 0 {
			first = out
		} else if out != first {
			t.Fatal("compile is not deterministic")
		}
	}
}

func TestCompilePreview_RefusalsDoNotQuoteVaultPaths(t *testing.T) {
	in, _ := mustParse(t, testIntentJSON("acme", "web", ""))
	base := "externalSecret:\n  data:\n    - secretKey: A\n      remoteKey: teams/other/secret-service\n"
	_, _, err := CompilePreview([]byte(base), in, "abc123", "h")
	if !errors.Is(err, ErrPreviewValuesRefused) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "teams/") || strings.Contains(err.Error(), "secret-service") {
		t.Errorf("the refusal quotes a Vault path: %v", err)
	}
}

// ── drift: the compiler's declared keys against the pinned snapshots ───────

var setLineRe = regexp.MustCompile(`^(?:\$\{PORT:\+)?--set(?:-string)? +(.+?)\}?\s*\\?$`)

// upstreamSetKeys extracts the --set keys of wft-preview-deploy.yaml.
func upstreamSetKeys(t *testing.T) []string {
	t.Helper()
	var keys []string
	for _, line := range strings.Split(string(readFile(t, filepath.Join(upstreamDir, "wft-preview-deploy.yaml"))), "\n") {
		m := setLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		rest := strings.Trim(m[1], `"`)
		key, _, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		keys = append(keys, strings.ReplaceAll(key, `\\`, `\`))
	}
	sort.Strings(keys)
	return keys
}

func TestUpstreamKeysMatchCompiler(t *testing.T) {
	got := upstreamSetKeys(t)
	want := append([]string(nil), previewSetKeys...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the --set keys of wft-preview-deploy.yaml changed.\nupstream: %q\ncompiler: %q\nUpdate CompilePreview and previewSetKeys together.", got, want)
	}

	// The yq assignments of tpl-git-commit.yaml in the families the intent
	// touches (probes, env, externalSecret, envFrom) must be exactly the
	// compiler's declared paths plus the "clear" forms it does not model.
	assignRe := regexp.MustCompile(`(\.[A-Za-z0-9_.\[\]()]+)\s*\+?=\s`)
	families := []string{".probes", ".env", ".externalSecret", ".envFrom"}
	inFamily := func(p string) bool {
		for _, f := range families {
			if p == f || strings.HasPrefix(p, f+".") || strings.HasPrefix(p, f+"[") {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(readFile(t, filepath.Join(upstreamDir, "tpl-git-commit.yaml"))), "\n") {
		if !strings.Contains(line, "yq eval -i") {
			continue
		}
		for _, m := range assignRe.FindAllStringSubmatch(line, -1) {
			if inFamily(m[1]) {
				seen[m[1]] = true
			}
		}
	}
	notModelled := []string{".probes.liveness", ".probes.readiness", ".env", ".externalSecret"} // null / clear forms
	allowed := map[string]bool{}
	for _, p := range append(append([]string(nil), intentYQPaths...), notModelled...) {
		allowed[p] = true
	}
	for p := range seen {
		if !allowed[p] {
			t.Errorf("tpl-git-commit.yaml assigns %s, which the compiler neither models nor lists as not modelled", p)
		}
	}
	for _, p := range intentYQPaths {
		if !seen[p] {
			t.Errorf("the compiler models %s but tpl-git-commit.yaml no longer assigns it", p)
		}
	}
}

// An empty or null values document is {} for the preview script
// (`yaml.safe_load(f) or {}`), so the plan must not refuse it.
func TestCompilePreview_EmptyBaseIsEmptyMapping(t *testing.T) {
	in, _ := mustParse(t, testIntentJSON("acme", "web", ""))
	for name, base := range map[string]string{"empty": "", "null": "null\n", "comment only": "# nothing\n"} {
		if _, _, err := CompilePreview([]byte(base), in, "abc123", "web-abc123.mctl.ai"); err != nil {
			t.Errorf("%s: err = %v, want nil", name, err)
		}
	}
}
