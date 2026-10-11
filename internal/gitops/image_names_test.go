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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const policyList = `# comment
registry ghcr.io/mctlhq
reserved-prefix mctl-
reserved portfolio
grant labs portfolio
grant labs mctl-telegram
grant platform mc
reserved mc
shared openclaw
grant labs openclaw
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
	// "platform" refuses even with a directory: it is never a tenant.
	for _, team := range []string{"labs", "ovk", "karabu", "platform"} {
		if err := os.MkdirAll(filepath.Join(root, "platform-gitops", "tenants", team), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	svc := filepath.Join(root, "platform-gitops", "services")
	writeFile(t, filepath.Join(svc, "labs", "portfolio", "values.yaml"), "image:\n  repository: ghcr.io/mctlhq/portfolio\n")
	// a preview that runs another name than its directory
	writeFile(t, filepath.Join(svc, "labs", "web-preview", "values.yaml"), "image:\n  repository: \"ghcr.io/mctlhq/web\"\n  tag: x\n")
	// openclaw services exist in several teams; only the shared line lets them share
	writeFile(t, filepath.Join(svc, "labs", "openclaw", "values.yaml"), "image:\n  repository: ghcr.io/mctlhq/mctl-openclaw\n")
	// another registry's image of the same name takes nothing here
	writeFile(t, filepath.Join(svc, "labs", "elsewhere", "values.yaml"), "image:\n  repository: ghcr.io/other/free\n")
	// a service that names no image at all
	writeFile(t, filepath.Join(svc, "labs", "no-image", "values.yaml"), "replicas: 1\n")
	// a dot-directory is not a team, as the script's globs skip it
	writeFile(t, filepath.Join(svc, ".hidden", "taken", "values.yaml"), "x: 1\n")
	// a service directory with no values yet still takes the name
	if err := os.MkdirAll(filepath.Join(svc, "karabu", "draw"), 0o750); err != nil {
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
		build, ok  bool
	}{
		{"labs", "portfolio", true, true},     // granted
		{"ovk", "portfolio", false, false},    // reserved, not granted to ovk
		{"labs", "mctl-telegram", true, true}, // granted despite the prefix
		{"ovk", "mctl-api", false, false},     // reserved prefix
		{"karabu", "openclaw", false, true},   // shared: any tenant may run it
		{"karabu", "openclaw", true, false},   // ... but only a grant may build it
		{"labs", "openclaw", true, true},      // the grant
		{"labs", "draw", false, false},        // karabu's directory
		{"karabu", "draw", true, true},        // own directory
		{"ovk", "web", false, false},          // an image labs runs
		{"labs", "web", true, true},
		{"ovk", "free", true, true},  // labs runs it from another registry
		{"ovk", "taken", true, true}, // only a dot-directory has it
		{"ovk", "brand-new", true, true},
		{"platform", "mc", true, false},     // the platform's grant is not a tenant's
		{"ghost", "brand-new", true, false}, // no tenants/ghost/
		{"ovk", "Bad_Name", false, false},
		{"", "x", false, false},
	}
	for _, c := range cases {
		err := p.Allowed(c.team, c.name, c.build)
		if (err == nil) != c.ok {
			t.Errorf("Allowed(%q, %q, build=%v) = %v, want ok=%v", c.team, c.name, c.build, err, c.ok)
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
	t.Run("missing tenants dir", func(t *testing.T) {
		root := checkout(t)
		if err := os.RemoveAll(filepath.Join(root, "platform-gitops", "tenants")); err != nil {
			t.Fatal(err)
		}
		if _, err := synced(root, time.Minute).ImageNamePolicy(); err == nil {
			t.Fatal("a missing tenants tree must be an error, not an empty one")
		}
	})
	t.Run("other registry", func(t *testing.T) {
		p, err := ParseImageNames([]byte(strings.Replace(policyList, "ghcr.io/mctlhq", "ghcr.io/other", 1)))
		if err != nil {
			t.Fatal(err)
		}
		p.AddTenant("ovk")
		if err := p.Allowed("ovk", "brand-new", false); err == nil {
			t.Fatal("a list governing another registry must refuse")
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
		"unknown line":    "registry r\nreserved-prefix mctl-\nallow labs x\n",
		"short grant":     "registry r\nreserved x\ngrant labs\n",
		"reserves none":   "registry r\n# nothing\ngrant labs x\n",
		"extra field":     "registry r\nreserved x y\n",
		"wildcard grant":  "registry r\nreserved x\ngrant * x\n",
		"no registry":     "reserved x\n",
		"two registries":  "registry r\nregistry s\nreserved x\n",
		"shared too long": "registry r\nreserved x\nshared a b\n",
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

func TestImageNamePolicy_RunsOtherImage(t *testing.T) {
	p, err := synced(checkout(t), time.Minute).ImageNamePolicy()
	if err != nil {
		t.Fatal(err)
	}
	for svc, want := range map[string]bool{
		"labs/portfolio":   false, // runs ghcr.io/mctlhq/portfolio
		"labs/openclaw":    true,  // runs mctl-openclaw
		"labs/web-preview": true,  // runs web
		"labs/elsewhere":   true,  // runs an image from another registry
		"labs/no-image":    false, // names no image
		"karabu/draw":      false, // no values.yaml
		"ovk/absent":       false, // no such service
	} {
		team, name, _ := strings.Cut(svc, "/")
		if got := p.RunsOtherImage(team, name); got != want {
			t.Errorf("RunsOtherImage(%s) = %v, want %v", svc, got, want)
		}
	}
}

func TestImageNamePolicy_DeployServiceBuilds(t *testing.T) {
	p, err := synced(checkout(t), time.Minute).ImageNamePolicy()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		action, repo, template, team, name string
		want                               bool
	}{
		{"update-config", "o/r", "default", "labs", "portfolio", false},
		{"deploy", "", "default", "labs", "portfolio", false},
		{"onboard", "o/r", "default", "labs", "brand-new", true},
		{"onboard", "o/r", "openclaw", "labs", "brand-new", false},
		{"deploy", "o/r", "default", "labs", "portfolio", true},
		{"deploy", "o/r", "default", "labs", "openclaw", false}, // runs mctl-openclaw
		{"deploy", "o/r", "default", "labs", "no-image", true},
		{"deploy", "o/r", "default", "karabu", "draw", true}, // no values.yaml
	}
	for _, c := range cases {
		if got := p.DeployServiceBuilds(c.action, c.repo, c.template, c.team, c.name); got != c.want {
			t.Errorf("DeployServiceBuilds(%+v) = %v", c, got)
		}
	}
}
