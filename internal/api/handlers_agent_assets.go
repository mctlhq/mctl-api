package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// Read-only agent asset index and preflight (mctl-api#748). Neither endpoint
// writes anything, grants anything or carries eligibility semantics: the
// preflight reports whether the CI-equivalent rules would pass, and the
// Python validators in mctl-gitops stay authoritative.

// requireAgentAssetsAdmin is requireAgentRegistryAdmin without the registry
// requirement: these endpoints still answer from gitops when the registry is
// not configured. 503 only when neither source exists.
func (h *Handlers) requireAgentAssetsAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.AgentRegistry == nil && h.opts.GitReader == nil {
		writeError(w, http.StatusServiceUnavailable, "neither agent registry nor gitops reader configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "agent registry is admin-only")
		return nil, false
	}
	return user, true
}

type sourceStatus struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func okSource() sourceStatus { return sourceStatus{Status: "ok"} }

func unavailableSource(reason string) sourceStatus {
	return sourceStatus{Status: "unavailable", Reason: reason}
}

func errSource(err error) sourceStatus {
	if err == nil {
		return okSource()
	}
	return unavailableSource(err.Error())
}

// readSnapshot returns the gitops snapshot, or a nil snapshot and the reason
// it is unavailable.
func (h *Handlers) readSnapshot() (*gitops.AgentPlatformSnapshot, error) {
	if h.opts.GitReader == nil {
		return nil, errors.New("gitops reader not configured")
	}
	return h.opts.GitReader.ReadAgentPlatformSnapshot()
}

type profileRefs struct {
	Tools               []string `json:"tools"`
	Skills              []string `json:"skills"`
	ModelPolicyTask     string   `json:"modelPolicyTask"`
	CapabilityProviders []string `json:"capabilityProviders"`
	PolicyRef           string   `json:"policyRef"`
}

func addRef(m map[string][]string, key, profile string) {
	if key == "" {
		return
	}
	m[key] = append(m[key], profile)
}

func sortRefs(m map[string][]string) {
	for k := range m {
		sort.Strings(m[k])
	}
}

// buildRefs computes the profile -> references map and its inverses from the
// given profiles.
func buildRefs(profiles []gitops.AgentPlatformProfile) map[string]any {
	byProfile := map[string]profileRefs{}
	skills := map[string][]string{}
	tools := map[string][]string{}
	policyRefs := map[string][]string{}
	tasks := map[string][]string{}
	providers := map[string][]string{}
	for i := range profiles {
		p := &profiles[i]
		pr := profileRefs{
			Tools:               append([]string{}, p.Spec.Tools...),
			Skills:              append([]string{}, p.Spec.Skills...),
			ModelPolicyTask:     p.Spec.ModelPolicyRef.Task,
			PolicyRef:           p.Spec.PolicyRef,
			CapabilityProviders: []string{},
		}
		if d := p.Spec.CapabilityDiscovery; d != nil {
			for _, prov := range d.Providers {
				pr.CapabilityProviders = append(pr.CapabilityProviders, prov.ID)
				addRef(providers, prov.ID, p.Name)
			}
		}
		byProfile[p.Name] = pr
		for _, s := range pr.Skills {
			addRef(skills, s, p.Name)
		}
		for _, t := range pr.Tools {
			addRef(tools, t, p.Name)
		}
		addRef(policyRefs, pr.PolicyRef, p.Name)
		addRef(tasks, pr.ModelPolicyTask, p.Name)
	}
	for _, m := range []map[string][]string{skills, tools, policyRefs, tasks, providers} {
		sortRefs(m)
	}
	return map[string]any{
		"profiles":            byProfile,
		"skills":              skills,
		"tools":               tools,
		"policyRefs":          policyRefs,
		"modelPolicyTasks":    tasks,
		"capabilityProviders": providers,
	}
}

// ListAgentAssets handles GET /api/v1/agent-assets: one merged, read-only
// index of registry catalog, gitops profiles, release intents, policy
// catalogs and platform skills, with reverse references.
func (h *Handlers) ListAgentAssets(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentAssetsAdmin(w, r); !ok {
		return
	}
	sources := map[string]sourceStatus{}
	resp := map[string]any{
		"sources":    sources,
		"registry":   nil,
		"profiles":   nil,
		"releases":   nil,
		"policy":     nil,
		"skills":     nil,
		"refs":       nil,
		"refs_scope": "gitops",
	}

	if h.opts.AgentRegistry == nil {
		sources["registry"] = unavailableSource("agent registry not configured")
	} else if catalog, err := h.opts.AgentRegistry.ListCatalog(r.Context()); err != nil {
		slog.Error("failed to list agent catalog", "error", err)
		sources["registry"] = unavailableSource("agent registry read failed")
	} else {
		if catalog == nil {
			catalog = []agentregistry.CatalogSummary{}
		}
		sources["registry"] = okSource()
		resp["registry"] = catalog
	}

	snap, snapErr := h.readSnapshot()
	if snapErr != nil {
		reason := snapErr.Error()
		for _, k := range []string{"gitops_profiles", "gitops_policy", "gitops_releases", "platform_skills"} {
			sources[k] = unavailableSource(reason)
		}
		resp["gitops_revision"] = ""
	} else {
		resp["gitops_revision"] = snap.Revision
		sources["gitops_profiles"] = errSource(snap.ProfilesErr)
		sources["gitops_policy"] = errSource(snap.PolicyErr)
		sources["gitops_releases"] = errSource(snap.ReleasesErr)
		sources["platform_skills"] = errSource(snap.SkillsErr)
		if snap.ProfilesErr == nil {
			resp["profiles"] = snap.Profiles
			resp["refs"] = buildRefs(snap.Profiles)
		}
		if snap.PolicyErr == nil {
			resp["policy"] = snap.Policy
		}
		if snap.ReleasesErr == nil {
			resp["releases"] = snap.Releases
		}
		if snap.SkillsErr == nil {
			resp["skills"] = snap.Skills
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func isRegistryNotFound(err error) bool {
	return errors.Is(err, agentregistry.ErrBindingNotFound) ||
		errors.Is(err, agentregistry.ErrDefinitionNotFound) ||
		errors.Is(err, agentregistry.ErrDefinitionVersionNotFound) ||
		errors.Is(err, agentregistry.ErrProfileVersionNotFound)
}

// PreflightAgent handles GET /api/v1/agents/{name}/preflight: runs the
// CI-equivalent rules against the resolved profile without committing or
// starting anything.
func (h *Handlers) PreflightAgent(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentAssetsAdmin(w, r); !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	sel, errMsg := parseBindingSelector(r)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}

	snap, snapErr := h.readSnapshot()
	facts := &registryFacts{}
	resp := map[string]any{"agent": agent}
	if sel.environment != "" {
		resp["environment"] = sel.environment
	}

	var spec *gitops.ExecutionProfileSpec
	var specErr error
	var definitionVersion, profileName, profileVersion string
	haveProfile := false

	// 1. Registry.
	if h.opts.AgentRegistry != nil {
		var resolved *agentregistry.ResolvedBinding
		var err error
		if sel.environment != "" {
			resolved, err = h.opts.AgentRegistry.ResolveBinding(r.Context(), agent, sel.environment)
		} else {
			resolved, err = h.opts.AgentRegistry.ResolveExplicit(r.Context(), agent, sel.definitionVersion, sel.profile, sel.profileVersion)
		}
		switch {
		case err == nil:
			haveProfile = true
			resp["source"] = "agentregistry"
			definitionVersion = resolved.Definition.Version
			profileName, profileVersion = resolved.Profile.Name, resolved.Profile.Version
			facts.resolved = true
			facts.defLifecycle = resolved.Definition.Lifecycle
			facts.profLifecycle = resolved.Profile.Lifecycle
			sat := resolved.Compatibility.Satisfied
			facts.compatSatisfied = &sat
			facts.compatRange = resolved.Compatibility.Range
			var s gitops.ExecutionProfileSpec
			if jerr := json.Unmarshal([]byte(resolved.Profile.Spec), &s); jerr != nil {
				specErr = errors.New("registry profile spec is not decodable: " + jerr.Error())
			} else {
				spec = &s
			}
		case isRegistryNotFound(err):
			// fall through to gitops
		default:
			slog.Error("failed to resolve agent from registry", "agent", agent, "error", err)
			facts.err = err
			resp["registry_error"] = "agent registry read failed"
		}
	}

	// 2. GitOps fallback.
	if !haveProfile {
		if snapErr != nil {
			writeError(w, http.StatusServiceUnavailable, "no registry binding and gitops unavailable: "+snapErr.Error())
			return
		}
		if snap.ProfilesErr != nil {
			writeError(w, http.StatusServiceUnavailable, "gitops profiles unavailable: "+snap.ProfilesErr.Error())
			return
		}
		resp["source"] = "gitops"
		var wantVersion string
		if sel.environment != "" {
			if snap.ReleasesErr != nil {
				writeError(w, http.StatusServiceUnavailable, "gitops release intents unavailable: "+snap.ReleasesErr.Error())
				return
			}
			var intent *gitops.AgentPlatformRelease
			for i := range snap.Releases {
				if snap.Releases[i].Agent == agent && snap.Releases[i].Environment == sel.environment {
					intent = &snap.Releases[i]
					break
				}
			}
			if intent != nil {
				resp["selection"] = "release-intent"
				profileName, wantVersion = intent.Profile.Name, intent.Profile.Version
				definitionVersion = intent.Definition.Version
				if lc := intent.RegistryLifecycle; len(lc) > 0 {
					facts.fromFixture = true
					facts.defLifecycle, facts.profLifecycle = lc["definition"], lc["profile"]
				}
			} else {
				resp["selection"] = "naming-convention"
				profileName = agent + "-default"
			}
		} else {
			resp["selection"] = "explicit"
			profileName, wantVersion = sel.profile, sel.profileVersion
			definitionVersion = sel.definitionVersion
		}
		for i := range snap.Profiles {
			if snap.Profiles[i].Name == profileName {
				spec = &snap.Profiles[i].Spec
				break
			}
		}
		if spec == nil {
			writeError(w, http.StatusNotFound, "no execution profile "+profileName+" for agent "+agent)
			return
		}
		profileVersion = spec.Version
		if wantVersion != "" && wantVersion != spec.Version {
			facts.versionMismatch = "gitops profile " + profileName + " has spec.version " + spec.Version + ", requested " + wantVersion
		}
	}

	// 3. Evaluate.
	var policy *gitops.AgentPlatformPolicy
	policyErr := snapErr
	if snapErr == nil {
		policy, policyErr = snap.Policy, snap.PolicyErr
	}
	checks := evaluatePreflight(spec, specErr, policy, policyErr, facts)

	sources := map[string]sourceStatus{}
	switch {
	case h.opts.AgentRegistry == nil:
		sources["registry"] = unavailableSource("agent registry not configured")
	case facts.err != nil:
		sources["registry"] = unavailableSource("agent registry read failed")
	default:
		sources["registry"] = okSource()
	}
	if snapErr != nil {
		sources["gitops_profiles"] = unavailableSource(snapErr.Error())
		sources["gitops_policy"] = unavailableSource(snapErr.Error())
		resp["gitops_revision"] = ""
	} else {
		sources["gitops_profiles"] = errSource(snap.ProfilesErr)
		sources["gitops_policy"] = errSource(snap.PolicyErr)
		sources["gitops_releases"] = errSource(snap.ReleasesErr)
		resp["gitops_revision"] = snap.Revision
	}
	resp["sources"] = sources
	resp["definition"] = map[string]string{"version": definitionVersion}
	resp["profile"] = map[string]string{"name": profileName, "version": profileVersion}
	resp["checks"] = checks
	resp["verdict"] = verdict(checks)
	writeJSON(w, http.StatusOK, resp)
}
