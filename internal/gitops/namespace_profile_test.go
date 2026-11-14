package gitops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const agentDeployYAML = "tenant:\n  name: pilot\n  profile: agent-deploy\n  members:\n    - userId: olga\n      role: owner\n"

const multiTeamAgentDeployYAML = `tenant:
  name: acme
  profile: agent-deploy
  teams:
    - name: web
    - name: data
`

// NamespaceProfile resolves a namespace to the tenant that owns it, a team
// namespace included, and reports that tenant's profile (mctl-api#1031).
func TestNamespaceProfile(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "pilot", agentDeployYAML)
	writeTenantYAML(t, dir, "acme", multiTeamAgentDeployYAML)
	writeTenantYAML(t, dir, "erpact", erpactYAML)

	for _, tt := range []struct {
		namespace, profile string
		owned              bool
	}{
		{"pilot", AgentDeployProfile, true},
		{"acme-web", AgentDeployProfile, true}, // a team namespace is its tenant's
		{"acme-data", AgentDeployProfile, true},
		{"erpact", "", true},               // no profile: ordinary
		{"acme", AgentDeployProfile, true}, // and the multi-team tenant's own name
		{"acme-ghost", "", false},          // no such team
		{"pilot-web", "", false},           // a single-team tenant has no team namespaces
		{"nobody", "", false},              // no such tenant
	} {
		profile, owned, err := r.NamespaceProfile(tt.namespace)
		if err != nil || profile != tt.profile || owned != tt.owned {
			t.Errorf("NamespaceProfile(%q) = %q, %v, %v; want %q, %v", tt.namespace, profile, owned, err, tt.profile, tt.owned)
		}
	}
}

// Nothing it could not read is an answer, and an unread profile is never
// "ordinary": the deploy gate rests on it.
func TestNamespaceProfile_UnreadableIsNeverOrdinary(t *testing.T) {
	refused := func(t *testing.T, r *Reader, namespace, want string) {
		t.Helper()
		profile, owned, err := r.NamespaceProfile(namespace)
		if err == nil {
			t.Fatalf("NamespaceProfile(%q) answered %q, %v", namespace, profile, owned)
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Fatalf("error %v does not mention %q", err, want)
		}
	}
	t.Run("never synced", func(t *testing.T) {
		dir, r := setupTempRepo(t)
		writeTenantYAML(t, dir, "pilot", agentDeployYAML)
		refused(t, r, "pilot", "never synced")
	})
	t.Run("stale checkout", func(t *testing.T) {
		dir, r := setupTempRepo(t)
		writeTenantYAML(t, dir, "pilot", agentDeployYAML)
		r.lastSync.Store(time.Now().Add(-CheckoutMaxAge - time.Minute).UnixNano())
		refused(t, r, "pilot", "")
	})
	t.Run("no tenants directory", func(t *testing.T) {
		_, r := syncedRepo(t)
		refused(t, r, "pilot", "tenants dir")
	})
	t.Run("malformed values of another tenant", func(t *testing.T) {
		// tenant.name, not the directory, names a tenant: a file that cannot
		// be parsed could be the owner.
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		writeTenantYAML(t, dir, "broken", "tenant: [not, a, mapping\n")
		refused(t, r, "erpact", "broken")
	})
	t.Run("directory without values that could own the namespace", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		for _, d := range []string{"pilot", "acme"} {
			if err := os.MkdirAll(filepath.Join(dir, "platform-gitops", "tenants", d), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		refused(t, r, "pilot", "pilot")
		refused(t, r, "acme-web", "acme")
		// One that cannot own it is not a tenant, as elsewhere.
		if p, owned, err := r.NamespaceProfile("erpact"); err != nil || p != "" || !owned {
			t.Fatalf("erpact = %q, %v, %v", p, owned, err)
		}
	})
	t.Run("unknown profile", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "pilot", strings.Replace(agentDeployYAML, "agent-deploy", "agent_deploy", 1))
		refused(t, r, "pilot", "unknown profile")
	})
	t.Run("namespace claimed twice", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "pilot", agentDeployYAML)
		writeTenantYAML(t, dir, "impostor", "tenant:\n  name: pilot\n")
		refused(t, r, "pilot", "claimed")
	})
	t.Run("empty namespace", func(t *testing.T) {
		_, r := syncedRepo(t)
		refused(t, r, "", "required")
	})
}
