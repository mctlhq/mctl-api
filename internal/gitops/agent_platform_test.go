package gitops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const apProfile = `kind: ExecutionProfile
metadata:
  name: a-default
spec:
  version: "1.0.0"
  skills: []
  tools: [Read]
  policyRef: p
  budgetUsd: 5
`

func apReader(t *testing.T, synced bool) (*Reader, string) {
	t.Helper()
	dir := t.TempDir()
	r := &Reader{localPath: dir}
	if synced {
		r.head = "deadbeef"
	}
	return r, filepath.Join(dir, "platform-gitops", "agent-platform")
}

func apWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAgentPlatform_ProfilesFailClosed(t *testing.T) {
	r, root := apReader(t, true)
	profs, rev, err := r.ListAgentPlatformProfiles()
	if err != nil || len(profs) != 0 || rev != "deadbeef" {
		t.Fatalf("missing dir: %v %v %q", profs, err, rev)
	}
	apWrite(t, filepath.Join(root, "execution-profiles", "a-default", "profile.yaml"), apProfile)
	profs, _, err = r.ListAgentPlatformProfiles()
	if err != nil || len(profs) != 1 || profs[0].Spec.BudgetUsd == nil || *profs[0].Spec.BudgetUsd != 5 || profs[0].Spec.Skills == nil {
		t.Fatalf("good profile: %+v %v", profs, err)
	}
	apWrite(t, filepath.Join(root, "execution-profiles", "b", "profile.yaml"), "kind: [unclosed")
	if _, _, err = r.ListAgentPlatformProfiles(); err == nil || !strings.Contains(err.Error(), "b/profile.yaml") {
		t.Fatalf("malformed must error naming the file, got %v", err)
	}
	apWrite(t, filepath.Join(root, "execution-profiles", "b", "profile.yaml"), strings.Replace(apProfile, "ExecutionProfile", "Other", 1))
	if _, _, err = r.ListAgentPlatformProfiles(); err == nil {
		t.Fatal("wrong kind must error")
	}
	apWrite(t, filepath.Join(root, "execution-profiles", "b", "profile.yaml"), apProfile)
	if _, _, err = r.ListAgentPlatformProfiles(); err == nil {
		t.Fatal("duplicate name must error")
	}
}

func TestAgentPlatform_SymlinkAndUnsynced(t *testing.T) {
	r, root := apReader(t, true)
	target := filepath.Join(t.TempDir(), "p.yaml")
	apWrite(t, target, apProfile)
	if err := os.MkdirAll(filepath.Join(root, "execution-profiles", "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "execution-profiles", "a", "profile.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ListAgentPlatformProfiles(); err == nil {
		t.Fatal("symlink must error")
	}
	u, _ := apReader(t, false)
	if _, _, err := u.ListAgentPlatformProfiles(); err == nil {
		t.Fatal("unsynced must error")
	}
	if _, err := u.ReadAgentPlatformSnapshot(); err == nil {
		t.Fatal("unsynced snapshot must error")
	}
}

func TestAgentPlatform_PolicyReleasesAndSnapshot(t *testing.T) {
	r, root := apReader(t, true)
	if _, _, err := r.GetAgentPlatformPolicy(); err != ErrAgentPlatformPolicyNotFound {
		t.Fatalf("missing policy: %v", err)
	}
	apWrite(t, filepath.Join(root, "policy.yaml"), `kind: AgentPlatformPolicy
spec:
  limits:
    maxBudgetUsd: 25
    maxTimeoutSeconds: 7200
  knownTools:
    - name: Read
  knownSkills: [s]
  knownMutationScopes:
    - name: m
      mutating: true
      requiresApproval: merge
  approvedSandboxes:
    - backend: argo
      clusterWorkflowTemplates: [c1]
`)
	p, _, err := r.GetAgentPlatformPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.Limits.MaxBudgetUsd == nil || *p.Limits.MaxBudgetUsd != 25 || len(p.KnownTools) != 1 || p.KnownTools[0] != "Read" ||
		len(p.KnownSkills) != 1 || p.KnownMutationScopes[0].RequiresApproval != "merge" || p.ApprovedSandboxes["argo"][0] != "c1" {
		t.Fatalf("policy decoded wrong: %+v", p)
	}
	apWrite(t, filepath.Join(root, "releases", "shadow", "a.yaml"), `kind: ReleaseBindingIntent
metadata:
  agent: a
  environment: shadow
spec:
  profile: {name: a-default, version: "1.0.0"}
  registryLifecycle: {definition: published, profile: published}
`)
	rel, _, err := r.ListAgentPlatformReleases()
	if err != nil || len(rel) != 1 || rel[0].Profile.Name != "a-default" || rel[0].RegistryLifecycle["profile"] != "published" {
		t.Fatalf("releases: %+v %v", rel, err)
	}
	// One broken source does not blank the others, and all share one revision.
	apWrite(t, filepath.Join(root, "execution-profiles", "x", "profile.yaml"), "kind: [")
	snap, err := r.ReadAgentPlatformSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ProfilesErr == nil || snap.PolicyErr != nil || snap.ReleasesErr != nil || snap.Policy == nil || len(snap.Releases) != 1 || snap.Revision != "deadbeef" {
		t.Fatalf("snapshot: %+v", snap)
	}
}
