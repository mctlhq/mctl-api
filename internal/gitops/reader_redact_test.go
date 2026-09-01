package gitops

import (
	"strings"
	"testing"
)

// A token containing characters net/url percent-encodes in userinfo. Not a
// current GitHub format — that is the point: the raw-bytes-only redactor
// passes every test written with a ghp_-shaped token and still leaks here.
const awkwardToken = "abc/def+ghi=jkl"

func TestRedactTokenCoversPercentEncodedForm(t *testing.T) {
	r := &Reader{token: awkwardToken}

	// What git echoes back is the encoded form, since the token was injected
	// through url.UserPassword when the clone URL was built.
	gitOutput := []byte("fatal: Authentication failed for " +
		"'https://x-access-token:abc%2Fdef+ghi=jkl@github.com/mctlhq/mctl-gitops/'")

	got := string(r.redactToken(gitOutput))
	if strings.Contains(got, "abc%2Fdef") {
		t.Fatalf("percent-encoded token survived redaction: %s", got)
	}
	if strings.Contains(got, awkwardToken) {
		t.Fatalf("raw token survived redaction: %s", got)
	}
}

func TestRedactTokenStillCoversRawForm(t *testing.T) {
	r := &Reader{token: "ghp_exampleTokenValue123"}
	got := string(r.redactToken([]byte("fatal: could not read Password for ghp_exampleTokenValue123")))
	if strings.Contains(got, "ghp_exampleTokenValue123") {
		t.Fatalf("raw token survived redaction: %s", got)
	}
}

func TestRedactTokenNoopWhenUnset(t *testing.T) {
	r := &Reader{}
	in := "fatal: repository not found"
	if got := string(r.redactToken([]byte(in))); got != in {
		t.Fatalf("output changed with no token set: %q", got)
	}
}
