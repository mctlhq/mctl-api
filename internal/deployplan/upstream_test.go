package deployplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

const upstreamDir = "testdata/upstream"

type upstreamProvenance struct {
	SourceRepo   string `json:"source_repo"`
	SourceCommit string `json:"source_commit"`
	CapturedAt   string `json:"captured_at"`
	Refresh      string `json:"refresh"`
	Files        []struct {
		SourcePath string `json:"source_path"`
		Snapshot   string `json:"snapshot"`
		SHA256     string `json:"sha256"`
	} `json:"files"`
}

// The snapshots every deployplan golden test depends on. A provenance file
// that silently drops one must fail, not shrink the check.
var requiredUpstreamSnapshots = []string{
	"wft-preview-deploy.yaml",
	"tpl-git-commit.yaml",
	"rewrite_preview_values.py",
}

func loadUpstreamProvenance(t *testing.T) upstreamProvenance {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(upstreamDir, "provenance.json"))
	if err != nil {
		t.Fatalf("reading provenance.json: %v", err)
	}
	var p upstreamProvenance
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("parsing provenance.json: %v", err)
	}
	return p
}

// TestUpstreamSnapshotsMatchProvenance pins each snapshot to the commit and
// hash it was captured at, so a hand edit to a fixture is caught.
func TestUpstreamSnapshotsMatchProvenance(t *testing.T) {
	p := loadUpstreamProvenance(t)
	if p.SourceRepo != "mctlhq/mctl-gitops" {
		t.Errorf("source_repo = %q, want mctlhq/mctl-gitops", p.SourceRepo)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.SourceCommit) {
		t.Errorf("source_commit %q is not a 40-hex commit SHA", p.SourceCommit)
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		seen[f.Snapshot] = true
		data, err := os.ReadFile(filepath.Join(upstreamDir, f.Snapshot))
		if err != nil {
			t.Errorf("snapshot %s: %v", f.Snapshot, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			t.Errorf("snapshot %s sha256 = %s, provenance says %s; refresh with %s instead of editing it", f.Snapshot, got, f.SHA256, p.Refresh)
		}
	}
	for _, name := range requiredUpstreamSnapshots {
		if !seen[name] {
			t.Errorf("provenance.json does not list required snapshot %s", name)
		}
	}
}

// TestUpstreamSnapshotsMatchSource compares the snapshots with the current
// mctl-gitops files. CI fetches them from mctl-gitops main into
// DEPLOYPLAN_UPSTREAM_SOURCE_DIR; without that variable the test is skipped,
// because nothing was observed. With it set, a missing source file is a
// failure, never a pass.
func TestUpstreamSnapshotsMatchSource(t *testing.T) {
	src := os.Getenv("DEPLOYPLAN_UPSTREAM_SOURCE_DIR")
	if src == "" {
		t.Skip("DEPLOYPLAN_UPSTREAM_SOURCE_DIR not set; drift is checked in CI")
	}
	p := loadUpstreamProvenance(t)
	for _, f := range p.Files {
		want, err := os.ReadFile(filepath.Join(src, f.Snapshot))
		if err != nil {
			t.Errorf("source %s: %v", f.SourcePath, err)
			continue
		}
		got, err := os.ReadFile(filepath.Join(upstreamDir, f.Snapshot))
		if err != nil {
			t.Errorf("snapshot %s: %v", f.Snapshot, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("snapshot %s (captured at %s@%s) differs from %s on mctl-gitops main; run %s and review the preview compiler against the change",
				f.Snapshot, p.SourceRepo, p.SourceCommit, f.SourcePath, p.Refresh)
		}
	}
}
