package gitops

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// TestImageNamePolicy_DeployBuildsMatchesTemplate runs DeployServiceBuilds
// and the build decision extracted from tpl-validate-tenant's validate on
// the same checkout, for every existing service and a new name, every
// action, with and without a dockerfile_repo and with both templates.
func TestImageNamePolicy_DeployBuildsMatchesTemplate(t *testing.T) {
	root := os.Getenv("IMAGE_NAMES_CHECKOUT")
	if root == "" {
		t.Skip("IMAGE_NAMES_CHECKOUT is not set")
	}
	p, err := synced(root, 0).ImageNamePolicy()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "platform-gitops", "argo-workflows", "cluster-templates", "tpl-validate-tenant.yaml")) //nolint:gosec // test input
	if err != nil {
		t.Fatal(err)
	}
	var tpl struct {
		Spec struct {
			Templates []struct {
				Name   string `yaml:"name"`
				Script struct {
					Source string `yaml:"source"`
				} `yaml:"script"`
			} `yaml:"templates"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &tpl); err != nil {
		t.Fatal(err)
	}
	var block string
	for _, tt := range tpl.Spec.Templates {
		if tt.Name == "validate" {
			if m := regexp.MustCompile(`(?ms)^BUILDS=false\n.*?\necho "\$BUILDS" > /tmp/builds$`).FindString(tt.Script.Source); m != "" {
				block = m
			}
		}
	}
	if block == "" {
		t.Fatal("could not extract validate's build decision")
	}

	type svc struct{ team, name string }
	services := []svc{{"labs", "brand-new"}}
	teams, err := os.ReadDir(filepath.Join(root, "platform-gitops", "services"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range teams {
		apps, err := os.ReadDir(filepath.Join(root, "platform-gitops", "services", tm.Name()))
		if err != nil {
			continue
		}
		for _, a := range apps {
			if a.IsDir() {
				services = append(services, svc{tm.Name(), a.Name()})
			}
		}
	}
	out := filepath.Join(t.TempDir(), "builds")
	script := "set -e\n" + strings.Replace(block, "/tmp/builds", out, 1)
	checked, builds := 0, 0
	for _, s := range services {
		for _, action := range []string{"onboard", "deploy", "update-config"} {
			for _, repo := range []string{"", "org/repo"} {
				for _, template := range []string{"default", "openclaw"} {
					cmd := exec.Command("sh", "-c", script) //nolint:gosec // test
					cmd.Dir = root
					cmd.Env = append(os.Environ(), "ACTION="+action, "TEAM="+s.team, "SERVICE="+s.name,
						"REPO="+repo, "SERVICE_TEMPLATE="+template, "PARAM_CONTAINER_REGISTRY="+ImageRegistry)
					if outp, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("decision block failed: %v: %s", err, outp)
					}
					got, err := os.ReadFile(out) //nolint:gosec // test output
					if err != nil {
						t.Fatal(err)
					}
					sh := strings.TrimSpace(string(got)) == "true"
					if goB := p.DeployServiceBuilds(action, repo, template, s.team, s.name); goB != sh {
						t.Errorf("%s/%s action=%s repo=%q template=%s: template builds=%v, DeployServiceBuilds=%v",
							s.team, s.name, action, repo, template, sh, goB)
					}
					checked++
					if sh {
						builds++
					}
				}
			}
		}
	}
	t.Logf("%d build decisions compared, %d build", checked, builds)
}
