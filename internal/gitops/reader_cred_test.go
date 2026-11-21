package gitops

import (
	"net/url"
	"strings"
	"testing"
)

func TestGitCredentialArgs_NoTokenInArgs(t *testing.T) {
	for _, token := range []string{"ghs_abc123", "p@ss/w:rd 1"} {
		args, env, err := gitCredentialArgs("https://github.com/mctlhq/mctl-gitops.git", token)
		if err != nil {
			t.Fatal(err)
		}
		enc := strings.TrimPrefix(url.UserPassword("x", token).String(), "x:")
		for _, a := range args {
			if strings.Contains(a, token) || strings.Contains(a, enc) {
				t.Errorf("arg leaks token: %q", a)
			}
		}
		found := false
		for _, e := range env {
			found = found || e == gitTokenEnv+"="+token
		}
		if !found {
			t.Error("env lacks token variable")
		}
		if !strings.Contains(strings.Join(args, " "), "credential.https://github.com.helper=") {
			t.Error("helper not scoped to host")
		}
	}
	if _, _, err := gitCredentialArgs("://bad", "t"); err == nil {
		t.Error("expected error for unparseable URL")
	}
}
