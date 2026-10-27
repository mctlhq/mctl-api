package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T20: the fixtures are synthetic; this repository is public.
func TestSupportFixtures_Hygiene(t *testing.T) {
	files, err := filepath.Glob("testdata/support/*")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	forbidden := []string{"sk-ant-", "gho_", "ghp_", "ghs_", "Bearer ", "mctl.ai", "@", "namax66", "karabu", "labs"}
	for _, f := range files {
		b, err := os.ReadFile(f)
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
	}
}
