package deployanalyze

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrDraftInvalid means the built draft failed schema validation. The draft
// is never returned in that case.
var ErrDraftInvalid = errors.New("draft intent failed schema validation")

var composeNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// Request is one analysis.
type Request struct {
	Tenant     string
	Repository string
	Revision   string
	Dockerfile string
	Context    string
	// BoundServices are the tenant's services built from Repository.
	BoundServices []string
}

// Detected summarises what was read from the Dockerfile.
type Detected struct {
	Port       *int   `json:"port,omitempty"`
	HealthPath string `json:"health_path,omitempty"`
	NonRoot    bool   `json:"non_root"`
	Stages     int    `json:"stages"`
}

// Binding is the tenant's services built from the repository.
type Binding struct {
	Tenant   string   `json:"tenant"`
	Services []string `json:"services"`
}

// Result is the analysis answer. It carries no raw file content, image,
// digest or secret field.
type Result struct {
	Supported   bool         `json:"supported"`
	Tier        string       `json:"tier,omitempty"`
	Repository  string       `json:"repository"`
	Revision    string       `json:"revision"`
	Dockerfile  string       `json:"dockerfile"`
	Context     string       `json:"context"`
	DraftIntent any          `json:"draft_intent"`
	NeedsInput  []NeedsInput `json:"needs_input"`
	Reason      Reason       `json:"reason,omitempty"`
	Message     string       `json:"message,omitempty"`
	Detected    Detected     `json:"detected"`
	Binding     Binding      `json:"binding"`
}

// Analyze reads the repository at the pinned commit and returns a verdict.
// It returns an error only for read failures or an invalid draft.
func Analyze(ctx context.Context, rd ContentReader, req Request) (*Result, error) {
	if req.Dockerfile == "" {
		req.Dockerfile = "Dockerfile"
	}
	if req.Context == "" {
		req.Context = "."
	}
	services := append([]string{}, req.BoundServices...)
	res := &Result{
		Repository: req.Repository,
		Revision:   req.Revision,
		Dockerfile: req.Dockerfile,
		Context:    req.Context,
		NeedsInput: []NeedsInput{},
		Binding:    Binding{Tenant: req.Tenant, Services: services},
	}
	unsupported := func(r Reason) (*Result, error) {
		res.Supported, res.Reason, res.Message = false, r, r.Message()
		res.NeedsInput = []NeedsInput{}
		res.DraftIntent = nil
		return res, nil
	}

	if err := rd.Commit(ctx, req.Repository, req.Revision); err != nil {
		return nil, err
	}
	df, err := rd.File(ctx, req.Repository, req.Revision, req.Dockerfile, MaxDockerfileBytes)
	if err != nil {
		return nil, err
	}
	switch {
	case df.Absent:
		return unsupported(ReasonNoDockerfile)
	case df.Kind != "file":
		return unsupported(ReasonDockerfileNotAFile)
	case df.TooLarge:
		return unsupported(ReasonDockerfileTooLarge)
	}
	parsed, perr := ParseDockerfile(df.Data)
	if perr != nil {
		var pe *parseError
		if errors.As(perr, &pe) {
			return unsupported(pe.reason)
		}
		return unsupported(ReasonDockerfileUnparseable)
	}

	var composes [][]byte
	var composeReason Reason
	for _, name := range composeNames {
		f, err := rd.File(ctx, req.Repository, req.Revision, name, MaxComposeBytes)
		if err != nil {
			return nil, err
		}
		switch {
		case f.Absent:
		case f.Kind != "file":
			if composeReason == "" {
				composeReason = ReasonComposeUnparseable
			}
		case f.TooLarge:
			if composeReason == "" {
				composeReason = ReasonComposeTooLarge
			}
		default:
			composes = append(composes, f.Data)
		}
	}
	if composeReason != "" {
		return unsupported(composeReason)
	}
	if r := detectCompose(composes); r != "" {
		return unsupported(r)
	}

	final := parsed.Final()
	res.Detected.Stages = len(parsed.Stages)
	if !detectUser(final) {
		return unsupported(ReasonRunsAsRoot)
	}
	res.Detected.NonRoot = true

	port, reason, need := detectPort(final)
	if reason != "" {
		return unsupported(reason)
	}
	res.Supported, res.Tier = true, "tier0"
	if need != nil {
		res.NeedsInput = append(res.NeedsInput, *need)
	} else {
		p := port
		res.Detected.Port = &p
	}
	healthPath, ok := detectHealth(final, port)
	if ok {
		res.Detected.HealthPath = healthPath
	} else {
		res.NeedsInput = append(res.NeedsInput, NeedsInput{Field: "runtime.healthPath", Reason: "health_path_not_determined"})
	}

	service := ""
	switch len(services) {
	case 1:
		service = services[0]
	case 0:
		service = normalizeServiceName(req.Repository)
	}
	if service == "" {
		n := NeedsInput{Field: "metadata.service", Reason: "service_not_determined"}
		for _, s := range services {
			n.Candidates = append(n.Candidates, s)
		}
		res.NeedsInput = append(res.NeedsInput, n)
	}

	if len(res.NeedsInput) > 0 {
		res.DraftIntent = nil
		return res, nil
	}
	draft := map[string]any{
		"apiVersion": "deploy.mctl.ai/v1alpha1",
		"kind":       "DeployIntent",
		"metadata":   map[string]any{"tenant": req.Tenant, "service": service},
		"spec": map[string]any{
			"environment": "preview",
			"source": map[string]any{
				"repository": req.Repository,
				"revision":   req.Revision,
				"dockerfile": req.Dockerfile,
				"context":    req.Context,
			},
			"detection": map[string]any{"tier": "tier0"},
			"runtime":   map[string]any{"port": port, "healthPath": healthPath, "replicas": 1},
			"exposure":  map[string]any{"mode": "internal"},
		},
	}
	if err := Validate(draft); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDraftInvalid, err)
	}
	res.DraftIntent = draft
	return res, nil
}

var (
	nonNameRe = regexp.MustCompile(`[^a-z0-9-]+`)
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)
)

// normalizeServiceName derives a service name from the repository name, or
// returns "" when the result does not match the schema's name pattern.
func normalizeServiceName(repo string) string {
	_, n, _ := strings.Cut(repo, "/")
	n = nonNameRe.ReplaceAllString(strings.ToLower(n), "-")
	n = strings.Trim(n, "-")
	if len(n) > 63 {
		n = strings.Trim(n[:63], "-")
	}
	if !nameRe.MatchString(n) {
		return ""
	}
	return n
}
