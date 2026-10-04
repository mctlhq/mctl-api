package gitops

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestImageNamePolicy_MatchesScript runs Allowed and check-image-name.sh on
// the same mctl-gitops checkout and compares every decision. Set
// IMAGE_NAMES_CHECKOUT to a checkout to run it; the two must change together.
func TestImageNamePolicy_MatchesScript(t *testing.T) {
	root := os.Getenv("IMAGE_NAMES_CHECKOUT")
	if root == "" {
		t.Skip("IMAGE_NAMES_CHECKOUT is not set")
	}
	script := filepath.Join(root, "platform-gitops", "argo-workflows", "scripts", "check-image-name.sh")
	p, err := synced(root, 0).ImageNamePolicy()
	if err != nil {
		t.Fatal(err)
	}

	teams := map[string]bool{"platform": true, "ghost": true}
	names := map[string]bool{"brand-new": true, "mctl-new": true}
	for _, dir := range []string{"tenants", "services"} {
		entries, err := os.ReadDir(filepath.Join(root, "platform-gitops", dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				teams[e.Name()] = true
			}
		}
	}
	for name := range p.owners {
		names[name] = true
	}
	f, err := os.Open(filepath.Join(root, ImageNamesFile)) //nolint:gosec // test input
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "#") && fields[0] != "registry" {
			names[fields[len(fields)-1]] = true
			if fields[0] == "grant" {
				teams[fields[1]] = true
			}
		}
	}

	sorted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	checked, allowed := 0, 0
	for _, team := range sorted(teams) {
		for _, name := range sorted(names) {
			for _, build := range []bool{false, true} {
				args := []string{script, "--tenant"}
				if build {
					args = append(args, "--build")
				}
				args = append(args, root, ImageRegistry, team, name)
				shOK := exec.Command("sh", args...).Run() == nil //nolint:gosec // test
				goErr := p.Allowed(team, name, build)
				if shOK != (goErr == nil) {
					t.Errorf("team=%s name=%s build=%v: script ok=%v, Allowed=%v", team, name, build, shOK, goErr)
				}
				checked++
				if shOK {
					allowed++
				}
			}
		}
	}
	t.Logf("%d decisions compared, %d allowed", checked, allowed)
}
