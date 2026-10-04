package gitops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const policyList = `# comment
reserved-prefix mctl-
reserved portfolio
grant labs portfolio
grant labs mctl-telegram
grant * openclaw
`

// synced returns a Reader over root whose last successful sync was age ago.
func synced(root string, age time.Duration) *Reader {
	r := &Reader{localPath: root}
	r.lastSync.Store(time.Now().Add(-age).UnixNano())
	return r
}

func checkout(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ImageNamesFile), policyList)
	svc := filepath.Join(root, "platform-gitops", "services")
	writeFile(t, filepath.Join(svc, "labs", "portfolio", "values.yaml"), "image:\n  repository: ghcr.io/mctlhq/portfolio\n")
	// a preview that runs another name than its directory
	writeFile(t, filepath.Join(svc, "labs", "web-preview", "values.yaml"), "image:\n  repository: \"ghcr.io/mctlhq/web\"\n  tag: x\n")
	// openclaw services exist in several teams; only the wildcard grant lets them share
	writeFile(t, filepath.Join(svc, "labs", "openclaw", "values.yaml"), "image:\n  repository: ghcr.io/mctlhq/mctl-openclaw\n")
	// a service directory with no values yet still takes the name
	if err := os.MkdirAll(filepath.Join(svc, "karabu", "draw"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestImageNamePolicy_Rule(t *testing.T) {
	r := synced(checkout(t), time.Minute)
	p, err := r.ImageNamePolicy()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		team, name string
		ok         bool
	}{
		{"labs", "portfolio", true},     // granted
		{"ovk", "portfolio", false},     // reserved, not granted to ovk
		{"labs", "mctl-telegram", true}, // granted despite the prefix
		{"ovk", "mctl-api", false},      // reserved prefix
		{"karabu", "openclaw", true},    // labs has one too; granted to every team
		{"labs", "draw", false},         // karabu's directory
		{"karabu", "draw", true},        // own directory
		{"ovk", "web", false},           // an image labs runs
		{"labs", "web", true},
		{"ovk", "brand-new", true},
		{"ovk", "Bad_Name", false},
		{"", "x", false},
	}
	for _, c := range cases {
		err := p.Allowed(c.team, c.name)
		if (err == nil) != c.ok {
			t.Errorf("Allowed(%q, %q) = %v, want ok=%v", c.team, c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrImageNameRefused) {
			t.Errorf("refusal must wrap ErrImageNameRefused: %v", err)
		}
	}
}

func TestImageNamePolicy_FailsClosed(t *testing.T) {
	t.Run("missing list", func(t *testing.T) {
		root := checkout(t)
		if err := os.Remove(filepath.Join(root, ImageNamesFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := synced(root, time.Minute).ImageNamePolicy(); err == nil {
			t.Fatal("a missing list must be an error")
		}
	})
	t.Run("missing services dir", func(t *testing.T) {
		root := checkout(t)
		if err := os.RemoveAll(filepath.Join(root, "platform-gitops", "services")); err != nil {
			t.Fatal(err)
		}
		if _, err := synced(root, time.Minute).ImageNamePolicy(); err == nil {
			t.Fatal("a missing services tree must be an error, not an empty one")
		}
	})
	for label, list := range map[string]string{
		"unknown line":  "reserved-prefix mctl-\nallow labs x\n",
		"short grant":   "reserved x\ngrant labs\n",
		"reserves none": "# nothing\ngrant labs x\n",
		"extra field":   "reserved x y\n",
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := ParseImageNames([]byte(list)); err == nil {
				t.Fatalf("%q must not parse", strings.TrimSpace(list))
			}
		})
	}
}

func TestImageNamePolicy_StaleCheckoutRefuses(t *testing.T) {
	root := checkout(t)
	if _, err := (&Reader{localPath: root}).ImageNamePolicy(); err == nil || !strings.Contains(err.Error(), "never synced") {
		t.Fatalf("a checkout that never synced must not answer: %v", err)
	}
	if _, err := synced(root, ImageNamePolicyMaxAge+time.Minute).ImageNamePolicy(); err == nil || !strings.Contains(err.Error(), "last synced") {
		t.Fatalf("a stale checkout must not answer: %v", err)
	}
	if _, err := synced(root, ImageNamePolicyMaxAge-time.Minute).ImageNamePolicy(); err != nil {
		t.Fatalf("a fresh checkout must answer: %v", err)
	}
}
