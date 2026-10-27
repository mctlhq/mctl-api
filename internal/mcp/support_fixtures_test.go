package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var fixtureTenant = regexp.MustCompile(`"tenant"\s*:\s*"([^"]*)"`)

// T20: the fixtures are synthetic; this repository is public.
func TestSupportFixtures_Hygiene(t *testing.T) {
	files, err := filepath.Glob("testdata/support/*")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	forbidden := []string{"sk-ant-", "gho_", "ghp_", "ghs_", "Bearer ", "mctl.ai", "@"}
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // files of testdata/support, from the glob above
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f, ".json") && !json.Valid(b) {
			t.Errorf("%s is not valid JSON", f)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains forbidden %q", f, bad)
			}
		}
		// Any tenant named in a fixture is the placeholder.
		for _, m := range fixtureTenant.FindAllStringSubmatch(string(b), -1) {
			if m[1] != "example-tenant" {
				t.Errorf("%s names tenant %q; only example-tenant is allowed", f, m[1])
			}
		}
	}
}
