package gitops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Read-only access to platform-gitops/agent-platform: execution profiles,
// the policy catalogs and release intents. Everything here is read under the
// reader's read lock together with the checkout revision, and fails closed:
// a file that exists but cannot be read, is not a regular file, does not
// parse or has the wrong kind is an error, never a shorter list. Only an
// absent directory in a synced checkout is an empty result.

const (
	kindExecutionProfile      = "ExecutionProfile"
	kindAgentPlatformPolicy   = "AgentPlatformPolicy"
	kindReleaseBindingIntent  = "ReleaseBindingIntent"
	agentPlatformRelativeRoot = "platform-gitops/agent-platform"
)

// ErrAgentPlatformPolicyNotFound means the checkout was read and has no
// agent-platform/policy.yaml.
var ErrAgentPlatformPolicyNotFound = errors.New("agent-platform policy.yaml not present in checkout")

// ExecutionProfileSpec is the part of an ExecutionProfile spec the preflight
// checks and the reverse-reference index need. Optional scalars are pointers
// so "absent" is distinguishable from zero. The json tags let the same struct
// decode a registry profile spec.
type ExecutionProfileSpec struct {
	Version        string `json:"version" yaml:"version"`
	ModelPolicyRef struct {
		Task          string `json:"task" yaml:"task"`
		Compatibility string `json:"compatibility" yaml:"compatibility"`
	} `json:"modelPolicyRef" yaml:"modelPolicyRef"`
	Skills      []string `json:"skills" yaml:"skills"`
	Tools       []string `json:"tools" yaml:"tools"`
	PolicyRef   string   `json:"policyRef" yaml:"policyRef"`
	Permissions struct {
		MutationScopes []string `json:"mutationScopes" yaml:"mutationScopes"`
	} `json:"permissions" yaml:"permissions"`
	BudgetUsd      *float64 `json:"budgetUsd" yaml:"budgetUsd"`
	TimeoutSeconds *float64 `json:"timeoutSeconds" yaml:"timeoutSeconds"`
	Runtime        struct {
		Sandbox struct {
			Backend                 string `json:"backend" yaml:"backend"`
			ClusterWorkflowTemplate string `json:"clusterWorkflowTemplate" yaml:"clusterWorkflowTemplate"`
			Approved                *bool  `json:"approved" yaml:"approved"`
		} `json:"sandbox" yaml:"sandbox"`
	} `json:"runtime" yaml:"runtime"`
	Approval struct {
		RequiredBefore []string `json:"requiredBefore" yaml:"requiredBefore"`
	} `json:"approval" yaml:"approval"`
	Evidence struct {
		Required []string `json:"required" yaml:"required"`
	} `json:"evidence" yaml:"evidence"`
	CapabilityDiscovery *CapabilityDiscoverySpec `json:"capabilityDiscovery" yaml:"capabilityDiscovery"`
}

// CapabilityDiscoverySpec is spec.capabilityDiscovery of an ExecutionProfile.
type CapabilityDiscoverySpec struct {
	Enabled   *bool `json:"enabled" yaml:"enabled"`
	Providers []struct {
		Type     string `json:"type" yaml:"type"`
		ID       string `json:"id" yaml:"id"`
		Alias    string `json:"alias" yaml:"alias"`
		Endpoint string `json:"endpoint,omitempty" yaml:"endpoint"`
	} `json:"providers" yaml:"providers"`
}

// AgentPlatformProfile is one execution-profiles/<dir>/profile.yaml.
type AgentPlatformProfile struct {
	Name string               `json:"name"`
	Dir  string               `json:"dir"`
	Path string               `json:"path"`
	Spec ExecutionProfileSpec `json:"-"`
	Raw  map[string]any       `json:"spec"`
}

// MutationScope is one policy.yaml knownMutationScopes entry.
type MutationScope struct {
	Name             string `json:"name" yaml:"name"`
	Mutating         bool   `json:"mutating" yaml:"mutating"`
	RequiresApproval string `json:"requiresApproval,omitempty" yaml:"requiresApproval"`
}

// AgentPlatformPolicy is the reference catalogs and ceilings of policy.yaml.
type AgentPlatformPolicy struct {
	Limits struct {
		MaxBudgetUsd      *float64 `json:"maxBudgetUsd" yaml:"maxBudgetUsd"`
		MaxTimeoutSeconds *float64 `json:"maxTimeoutSeconds" yaml:"maxTimeoutSeconds"`
	} `json:"limits" yaml:"limits"`
	KnownTools            []string        `json:"knownTools" yaml:"-"`
	KnownSkills           []string        `json:"knownSkills" yaml:"knownSkills"`
	KnownModelPolicyTasks []string        `json:"knownModelPolicyTasks" yaml:"knownModelPolicyTasks"`
	KnownPolicies         []string        `json:"knownPolicies" yaml:"knownPolicies"`
	KnownApprovalGates    []string        `json:"knownApprovalGates" yaml:"knownApprovalGates"`
	KnownEvidenceKinds    []string        `json:"knownEvidenceKinds" yaml:"knownEvidenceKinds"`
	KnownMutationScopes   []MutationScope `json:"knownMutationScopes" yaml:"knownMutationScopes"`
	// ApprovedSandboxes maps backend to its approved ClusterWorkflowTemplates.
	ApprovedSandboxes map[string][]string `json:"approvedSandboxes" yaml:"-"`
}

// AgentPlatformRelease is one releases/<env>/<agent>.yaml ReleaseBindingIntent.
type AgentPlatformRelease struct {
	Agent       string `json:"agent"`
	Environment string `json:"environment"`
	Path        string `json:"path"`
	Definition  struct {
		Name    string `json:"name" yaml:"name"`
		Version string `json:"version" yaml:"version"`
	} `json:"definition"`
	Profile struct {
		Name    string `json:"name" yaml:"name"`
		Version string `json:"version" yaml:"version"`
	} `json:"profile"`
	BindingSource     string            `json:"bindingSource"`
	Promotable        *bool             `json:"promotable"`
	RegistryLifecycle map[string]string `json:"registryLifecycle,omitempty"`
}

// AgentPlatformSnapshot is every agent-platform source read under one lock,
// so all parts share one Revision. Each part carries its own error: one
// unreadable source does not blank the others.
type AgentPlatformSnapshot struct {
	Revision    string
	Profiles    []AgentPlatformProfile
	ProfilesErr error
	Policy      *AgentPlatformPolicy
	PolicyErr   error
	Releases    []AgentPlatformRelease
	ReleasesErr error
	Skills      []PlatformSkill
	SkillsErr   error
}

type agentPlatformDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string `yaml:"name"`
		Agent       string `yaml:"agent"`
		Environment string `yaml:"environment"`
	} `yaml:"metadata"`
}

// ListAgentPlatformProfiles reads every execution profile and the checkout revision.
func (r *Reader) ListAgentPlatformProfiles() ([]AgentPlatformProfile, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rev, err := r.revisionLocked()
	if err != nil {
		return nil, "", fmt.Errorf("gitops checkout unavailable: %w", err)
	}
	out, err := r.listAgentPlatformProfilesLocked()
	return out, rev, err
}

// GetAgentPlatformPolicy reads agent-platform/policy.yaml and the checkout revision.
func (r *Reader) GetAgentPlatformPolicy() (*AgentPlatformPolicy, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rev, err := r.revisionLocked()
	if err != nil {
		return nil, "", fmt.Errorf("gitops checkout unavailable: %w", err)
	}
	p, err := r.getAgentPlatformPolicyLocked()
	return p, rev, err
}

// ListAgentPlatformReleases reads every release intent and the checkout revision.
func (r *Reader) ListAgentPlatformReleases() ([]AgentPlatformRelease, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rev, err := r.revisionLocked()
	if err != nil {
		return nil, "", fmt.Errorf("gitops checkout unavailable: %w", err)
	}
	out, err := r.listAgentPlatformReleasesLocked()
	return out, rev, err
}

// ReadAgentPlatformSnapshot reads profiles, policy, release intents and
// platform skills under a single read lock. The error is non-nil only when
// the checkout itself is unavailable; per-source failures are in the parts.
func (r *Reader) ReadAgentPlatformSnapshot() (*AgentPlatformSnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rev, err := r.revisionLocked()
	if err != nil {
		return nil, fmt.Errorf("gitops checkout unavailable: %w", err)
	}
	snap := &AgentPlatformSnapshot{Revision: rev}
	snap.Profiles, snap.ProfilesErr = r.listAgentPlatformProfilesLocked()
	snap.Policy, snap.PolicyErr = r.getAgentPlatformPolicyLocked()
	snap.Releases, snap.ReleasesErr = r.listAgentPlatformReleasesLocked()
	snap.Skills, snap.SkillsErr = r.listPlatformSkillsLocked()
	return snap, nil
}

func (r *Reader) agentPlatformRoot() string {
	return filepath.Join(r.localPath, filepath.FromSlash(agentPlatformRelativeRoot))
}

// readAgentPlatformFile Lstats rel (non-regular is an error), reads it and
// decodes the kind/metadata header. exists=false means the file is absent.
func (r *Reader) readAgentPlatformFile(rel, wantKind string) (data []byte, doc agentPlatformDoc, exists bool, err error) {
	path := filepath.Join(r.localPath, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, doc, false, nil
		}
		return nil, doc, false, fmt.Errorf("reading %s: %w", rel, err)
	}
	if !info.Mode().IsRegular() {
		return nil, doc, true, fmt.Errorf("%s is not a regular file", rel)
	}
	data, err = os.ReadFile(path) //nolint:gosec // fixed layout inside the checkout, regular file
	if err != nil {
		return nil, doc, true, fmt.Errorf("reading %s: %w", rel, err)
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, doc, true, fmt.Errorf("parsing %s: %w", rel, err)
	}
	if doc.Kind != wantKind {
		return nil, doc, true, fmt.Errorf("%s: kind is %q, want %q", rel, doc.Kind, wantKind)
	}
	return data, doc, true, nil
}

// readAgentPlatformDir lists the entries of a directory under agent-platform.
// A missing directory is (nil, nil); a symlink or unreadable directory is an error.
func (r *Reader) readAgentPlatformDir(sub string) ([]os.DirEntry, error) {
	dir := filepath.Join(r.agentPlatformRoot(), filepath.FromSlash(sub))
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s/%s: %w", agentPlatformRelativeRoot, sub, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s/%s is not a directory", agentPlatformRelativeRoot, sub)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s/%s: %w", agentPlatformRelativeRoot, sub, err)
	}
	return entries, nil
}

func (r *Reader) listAgentPlatformProfilesLocked() ([]AgentPlatformProfile, error) {
	entries, err := r.readAgentPlatformDir("execution-profiles")
	if err != nil {
		return nil, err
	}
	out := []AgentPlatformProfile{}
	seen := map[string]string{}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s/execution-profiles/%s is not a regular directory", agentPlatformRelativeRoot, entry.Name())
		}
		if !entry.IsDir() {
			continue
		}
		rel := agentPlatformRelativeRoot + "/execution-profiles/" + entry.Name() + "/profile.yaml"
		data, doc, exists, err := r.readAgentPlatformFile(rel, kindExecutionProfile)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		if doc.Metadata.Name == "" {
			return nil, fmt.Errorf("%s: metadata.name is required", rel)
		}
		if prev, ok := seen[doc.Metadata.Name]; ok {
			return nil, fmt.Errorf("duplicate execution profile name %q in %s and %s", doc.Metadata.Name, prev, rel)
		}
		seen[doc.Metadata.Name] = rel
		var full struct {
			Spec ExecutionProfileSpec `yaml:"spec"`
		}
		if err := yaml.Unmarshal(data, &full); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", rel, err)
		}
		var raw struct {
			Spec map[string]any `yaml:"spec"`
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", rel, err)
		}
		out = append(out, AgentPlatformProfile{
			Name: doc.Metadata.Name, Dir: entry.Name(), Path: rel, Spec: full.Spec, Raw: raw.Spec,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Reader) getAgentPlatformPolicyLocked() (*AgentPlatformPolicy, error) {
	rel := agentPlatformRelativeRoot + "/policy.yaml"
	data, _, exists, err := r.readAgentPlatformFile(rel, kindAgentPlatformPolicy)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrAgentPlatformPolicyNotFound
	}
	var doc struct {
		Spec struct {
			AgentPlatformPolicy `yaml:",inline"`
			KnownTools          []struct {
				Name string `yaml:"name"`
			} `yaml:"knownTools"`
			ApprovedSandboxes []struct {
				Backend                  string   `yaml:"backend"`
				ClusterWorkflowTemplates []string `yaml:"clusterWorkflowTemplates"`
			} `yaml:"approvedSandboxes"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", rel, err)
	}
	p := doc.Spec.AgentPlatformPolicy
	// The inline struct is a decode target for the plain fields only; its
	// limits tag is "limits", which is inline-decoded too.
	p.KnownTools = []string{}
	for _, t := range doc.Spec.KnownTools {
		p.KnownTools = append(p.KnownTools, t.Name)
	}
	p.ApprovedSandboxes = map[string][]string{}
	for _, s := range doc.Spec.ApprovedSandboxes {
		p.ApprovedSandboxes[s.Backend] = append(p.ApprovedSandboxes[s.Backend], s.ClusterWorkflowTemplates...)
	}
	return &p, nil
}

func (r *Reader) listAgentPlatformReleasesLocked() ([]AgentPlatformRelease, error) {
	envs, err := r.readAgentPlatformDir("releases")
	if err != nil {
		return nil, err
	}
	out := []AgentPlatformRelease{}
	for _, env := range envs {
		if env.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s/releases/%s is not a regular directory", agentPlatformRelativeRoot, env.Name())
		}
		if !env.IsDir() {
			continue
		}
		files, err := r.readAgentPlatformDir("releases/" + env.Name())
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}
			rel := agentPlatformRelativeRoot + "/releases/" + env.Name() + "/" + f.Name()
			data, doc, _, err := r.readAgentPlatformFile(rel, kindReleaseBindingIntent)
			if err != nil {
				return nil, err
			}
			var body struct {
				Spec struct {
					Definition struct {
						Name    string `yaml:"name"`
						Version string `yaml:"version"`
					} `yaml:"definition"`
					Profile struct {
						Name    string `yaml:"name"`
						Version string `yaml:"version"`
					} `yaml:"profile"`
					BindingSource     string            `yaml:"bindingSource"`
					Promotable        *bool             `yaml:"promotable"`
					RegistryLifecycle map[string]string `yaml:"registryLifecycle"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal(data, &body); err != nil {
				return nil, fmt.Errorf("parsing %s: %w", rel, err)
			}
			rel2 := AgentPlatformRelease{
				Agent: doc.Metadata.Agent, Environment: doc.Metadata.Environment, Path: rel,
				BindingSource: body.Spec.BindingSource, Promotable: body.Spec.Promotable,
				RegistryLifecycle: body.Spec.RegistryLifecycle,
			}
			rel2.Definition.Name, rel2.Definition.Version = body.Spec.Definition.Name, body.Spec.Definition.Version
			rel2.Profile.Name, rel2.Profile.Version = body.Spec.Profile.Name, body.Spec.Profile.Version
			if rel2.Agent == "" || rel2.Environment == "" {
				return nil, fmt.Errorf("%s: metadata.agent and metadata.environment are required", rel)
			}
			out = append(out, rel2)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Environment != out[j].Environment {
			return out[i].Environment < out[j].Environment
		}
		return out[i].Agent < out[j].Agent
	})
	return out, nil
}
