package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/gitops"
)

// A tenant build pushes ghcr.io/mctlhq/<component_name> and a tenant service
// runs it, so a non-admin may only use image names the reviewed list in
// mctl-gitops does not reserve and no other team already has, and only as
// an existing tenant. Checked before anything else about the build, and an
// unreadable list refuses.

func imagePolicy(t *testing.T, list string, owners map[string]string) *gitops.ImageNamePolicy {
	t.Helper()
	p, err := gitops.ParseImageNames([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	p.AddTenant("tests")
	p.AddTenant("karabu")
	for name, team := range owners {
		p.AddOwner(name, team)
	}
	return p
}

const testImageList = `
registry ghcr.io/mctlhq
reserved-prefix mctl-
reserved portfolio
grant tests mctl-docs
shared openclaw
`

func imageGateRouter(t *testing.T, git *fakeGitReader) (http.Handler, *fakeExecutor, *gateFixture) {
	t.Helper()
	git.tenants = []gitops.Tenant{{Name: "tests", DisplayName: "Tests", Quotas: map[string]string{"pods": "10"}}}
	router, exec, f := newGateRouterWith(t, "gac-token", git)
	f.binding = bindingAnswer(true)
	return router, exec, f
}

func onboardAs(name string) map[string]string {
	in := onboard("myorg/my-app")
	in["component_name"] = name
	return in
}

func TestImageNameGate_RefusesReservedAndForeignNames(t *testing.T) {
	git := &fakeGitReader{imagePolicy: imagePolicy(t, testImageList, map[string]string{"shop": "karabu"})}
	cases := map[string]string{
		"platform prefix": "mctl-api",
		"reserved name":   "portfolio",
		"other team":      "shop",
	}
	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			router, exec, f := imageGateRouter(t, git)
			w := postAs(t, router, deployPath, onboardAs(name), ownerUser)
			assertStatus(t, w, http.StatusForbidden)
			if !strings.Contains(w.Body.String(), name) {
				t.Errorf("refusal should name %q: %s", name, w.Body.String())
			}
			if len(exec.submittedParams) != 0 {
				t.Fatal("refused build must not be submitted")
			}
			if len(f.bindingCalls()) != 0 {
				t.Errorf("the image name is checked before the repository: %v", f.bindingCalls())
			}
		})
	}
}

func TestImageNameGate_RefusesPreviewOfReservedName(t *testing.T) {
	git := &fakeGitReader{imagePolicy: imagePolicy(t, testImageList, nil)}
	router, exec, _ := imageGateRouter(t, git)
	w := postAs(t, router, "/api/v1/operations/preview-deploy/execute", map[string]string{
		"team_name": "tests", "component_name": "mctl-portal", "image_tag": "4.17.2",
	}, ownerUser)
	assertStatus(t, w, http.StatusForbidden)
	if len(exec.submittedParams) != 0 {
		t.Fatal("refused preview must not be submitted")
	}
}

func TestImageNameGate_AllowsOwnGrantedAndNewNames(t *testing.T) {
	git := &fakeGitReader{imagePolicy: imagePolicy(t, testImageList, map[string]string{"my-app": "tests", "shop": "karabu"})}
	for _, name := range []string{"my-app", "mctl-docs", "brand-new"} {
		t.Run(name, func(t *testing.T) {
			router, exec, _ := imageGateRouter(t, git)
			w := postAs(t, router, deployPath, onboardAs(name), ownerUser)
			assertStatus(t, w, http.StatusAccepted)
			if len(exec.submittedParams) != 1 {
				t.Fatal("expected a submission")
			}
		})
	}
}

func TestImageNameGate_UnreadablePolicyRefuses(t *testing.T) {
	git := &fakeGitReader{imagePolicyErr: errors.New("reading image-names.txt: no such file")}
	router, exec, _ := imageGateRouter(t, git)
	w := postAs(t, router, deployPath, onboardAs("my-app"), ownerUser)
	assertStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "image name policy") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if len(exec.submittedParams) != 0 {
		t.Fatal("must not submit without a readable policy")
	}
}

func TestImageNameGate_AdminsAreNotChecked(t *testing.T) {
	git := &fakeGitReader{imagePolicyErr: errors.New("would refuse")}
	router, exec, _ := imageGateRouter(t, git)
	w := postAs(t, router, deployPath, onboardAs("mctl-api"), adminUser)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 {
		t.Fatal("expected a submission")
	}
}

// A shared name may be run by any tenant but built only by a granted one, and
// "builds" follows the workflows: deploy-service with a dockerfile_repo
// (except the openclaw template), preview-deploy with a git_ref.
func TestImageNameGate_SharedNameRunsButDoesNotBuild(t *testing.T) {
	policy := imagePolicy(t, testImageList, nil)
	// tests/openclaw runs mctl-openclaw, so deploy-service does not build it
	// even when service_template is left at its default.
	policy.AddRunsOther("tests", "openclaw")
	git := &fakeGitReader{imagePolicy: policy}
	const previewPath = "/api/v1/operations/preview-deploy/execute"
	runOpenclawTemplate := onboardAs("openclaw")
	runOpenclawTemplate["service_template"] = "openclaw"
	updateConfig := map[string]string{"action": "update-config", "team_name": "tests", "component_name": "openclaw", "dockerfile_repo": "myorg/my-app", "image_tag": "1.0.0"}
	deployExisting := map[string]string{"action": "deploy", "team_name": "tests", "component_name": "openclaw", "dockerfile_repo": "myorg/my-app", "git_tag": "v1.0.0"}
	cases := []struct {
		label string
		path  string
		input map[string]string
		want  int
	}{
		{"deploy of a service running another image runs", deployPath, deployExisting, http.StatusAccepted},
		{"onboard builds", deployPath, onboardAs("openclaw"), http.StatusForbidden},
		{"openclaw template runs a fixed image", deployPath, runOpenclawTemplate, http.StatusAccepted},
		{"update-config runs", deployPath, updateConfig, http.StatusAccepted},
		{"preview of a tag runs", previewPath, map[string]string{"team_name": "tests", "component_name": "openclaw", "image_tag": "1.0.0"}, http.StatusAccepted},
		{"preview of a branch builds", previewPath, map[string]string{"team_name": "tests", "component_name": "openclaw", "git_ref": "main", "dockerfile_repo": "myorg/my-app"}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			router, exec, _ := imageGateRouter(t, git)
			w := postAs(t, router, c.path, c.input, ownerUser)
			assertStatus(t, w, c.want)
			if submitted := len(exec.submittedParams) == 1; submitted != (c.want == http.StatusAccepted) {
				t.Fatalf("submitted=%v for status %d", submitted, c.want)
			}
		})
	}
}

// The team must be a tenant in the checkout the policy was read from, and
// the list must govern the registry the workflows use.
func TestImageNameGate_RefusesUnknownTenantAndForeignRegistry(t *testing.T) {
	noTenant, err := gitops.ParseImageNames([]byte(testImageList))
	if err != nil {
		t.Fatal(err)
	}
	otherRegistry := imagePolicy(t, strings.Replace(testImageList, "ghcr.io/mctlhq", "ghcr.io/elsewhere", 1), nil)
	for label, p := range map[string]*gitops.ImageNamePolicy{"no tenant dir": noTenant, "other registry": otherRegistry} {
		t.Run(label, func(t *testing.T) {
			router, exec, _ := imageGateRouter(t, &fakeGitReader{imagePolicy: p})
			w := postAs(t, router, deployPath, onboardAs("brand-new"), ownerUser)
			assertStatus(t, w, http.StatusForbidden)
			if len(exec.submittedParams) != 0 {
				t.Fatal("refused build must not be submitted")
			}
		})
	}
}

// A deploy of an existing service that runs its own image builds it, so a
// shared name is refused there as on onboard.
func TestImageNameGate_DeployOfOwnImageBuilds(t *testing.T) {
	git := &fakeGitReader{imagePolicy: imagePolicy(t, testImageList, nil)}
	router, exec, _ := imageGateRouter(t, git)
	w := postAs(t, router, deployPath, map[string]string{
		"action": "deploy", "team_name": "tests", "component_name": "openclaw",
		"dockerfile_repo": "myorg/my-app", "git_tag": "v1.0.0",
	}, ownerUser)
	assertStatus(t, w, http.StatusForbidden)
	if len(exec.submittedParams) != 0 {
		t.Fatal("refused build must not be submitted")
	}
}
