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
// mctl-gitops does not reserve and no other team already has. Checked before
// anything else about the build, and an unreadable list refuses.

func imagePolicy(t *testing.T, list string, owners map[string]string) *gitops.ImageNamePolicy {
	t.Helper()
	p, err := gitops.ParseImageNames([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	for name, team := range owners {
		p.AddOwner(name, team)
	}
	return p
}

const testImageList = `
reserved-prefix mctl-
reserved portfolio
grant tests mctl-docs
grant * openclaw
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
	for _, name := range []string{"my-app", "mctl-docs", "openclaw", "brand-new"} {
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
