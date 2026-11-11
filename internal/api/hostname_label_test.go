package api

import (
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/operations"
)

func TestHostnameLabelPatternDerivedFromOperations(t *testing.T) {
	if got, want := hostnameLabelPattern.String(), "^"+operations.HostnameLabelPattern+"$"; got != want {
		t.Fatalf("pattern drift: %q != %q", got, want)
	}
	for l, want := range map[string]bool{
		"a": true, "xn--p1ai": true, "a-b": true, "-a": false, "a-": false, "A": false,
		strings.Repeat("a", 63): true, strings.Repeat("a", 64): false,
	} {
		if got := hostnameLabelPattern.MatchString(l); got != want {
			t.Errorf("%q = %v, want %v", l, got, want)
		}
	}
}

func TestCIRelativePathMatchesRegistryRule(t *testing.T) {
	for p, want := range map[string]bool{
		"Dockerfile": true, ".docker/Dockerfile": true, "docker/prod.Dockerfile": true,
		".": false, "..": false, "../x": false, "a/../b": false, "/abs": false,
		"-x": false, "a//b": false, "a/-b": false, strings.Repeat("a", 257): false,
	} {
		if got := ciRelativePath(p); got != want {
			t.Errorf("%q = %v, want %v", p, got, want)
		}
	}
}
