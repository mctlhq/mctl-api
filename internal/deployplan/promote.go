package deployplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Promote (mctl-api#1049): a plan whose "intent" is a pointer to one
// successful preview DeployRecord. It carries the preview's image tag and
// digest, bound by the plan digest, and applies by pinning both in the
// service's production values through the promote-deployment workflow. The
// digest is never a caller input: it is read from the record here.

// PromoteIntentKind labels the stored intent of a promote plan.
const PromoteIntentKind = "mctl-promote-intent/v1"

var (
	// ErrPromoteIntent is a stored promote intent that does not parse.
	ErrPromoteIntent = errors.New("deployplan: the promote intent is not valid")
	// ErrPromoteValues is a production values file a promotion cannot be
	// written into: no image block with a repository.
	ErrPromoteValues = errors.New("deployplan: the service's values cannot take a promotion")

	imageTagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	depIDRE    = regexp.MustCompile(`^dep_[0-9a-f-]{36}$`)
)

// PromoteIntent is what a promote plan binds besides the tenant, service and
// the production values it changes.
type PromoteIntent struct {
	Kind               string `json:"kind"`
	Tenant             string `json:"tenant"`
	Service            string `json:"service"`
	SourceDeploymentID string `json:"source_deployment_id"`
	ImageTag           string `json:"image_tag"`
	ImageDigest        string `json:"image_digest"`
}

// Canonical is the stored, digested form: fixed field order, no spaces.
func (i PromoteIntent) Canonical() (string, error) {
	i.Kind = PromoteIntentKind
	if err := i.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPromoteIntent, err)
	}
	return string(b), nil
}

func (i PromoteIntent) validate() error {
	switch {
	case i.Kind != PromoteIntentKind:
		return fmt.Errorf("%w: kind", ErrPromoteIntent)
	case i.Tenant == "" || i.Service == "":
		return fmt.Errorf("%w: tenant and service", ErrPromoteIntent)
	case !depIDRE.MatchString(i.SourceDeploymentID):
		return fmt.Errorf("%w: source_deployment_id", ErrPromoteIntent)
	case !imageTagRE.MatchString(i.ImageTag):
		return fmt.Errorf("%w: image_tag", ErrPromoteIntent)
	case !ValidImageDigest(i.ImageDigest):
		return fmt.Errorf("%w: image_digest", ErrPromoteIntent)
	}
	return nil
}

// ParsePromoteIntent reads a stored promote intent. Unknown fields, trailing
// data and any text that is not the canonical rendering are refused.
func ParsePromoteIntent(canonical string) (PromoteIntent, error) {
	var i PromoteIntent
	dec := json.NewDecoder(bytes.NewReader([]byte(canonical)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&i); err != nil || dec.More() {
		return PromoteIntent{}, fmt.Errorf("%w: unreadable", ErrPromoteIntent)
	}
	if err := i.validate(); err != nil {
		return PromoteIntent{}, err
	}
	if again, err := i.Canonical(); err != nil || again != canonical {
		return PromoteIntent{}, fmt.Errorf("%w: not canonical", ErrPromoteIntent)
	}
	return i, nil
}

// PromoteTag is the image tag a preview apply builds: preview-deploy is
// submitted with image_tag "rev-<revision>".
func PromoteTag(rec *Record) string { return "rev-" + rec.Revision }

// PromoteSourceUnusable says why a record cannot be promoted, or "" when it
// can. Only a preview that was submitted, succeeded, was observed healthy and
// reported the digest it ran is a verified preview: unknown is never treated
// as verified.
func PromoteSourceUnusable(rec *Record) string {
	switch {
	case rec.Environment != EnvironmentPreview:
		return "the deployment is not a preview"
	case rec.Status != RecordSubmitted:
		return "the preview was not submitted"
	case rec.RunResult != RunSucceeded:
		return "the preview did not succeed"
	case rec.Health != HealthHealthy:
		return "the preview was not observed healthy"
	case !ValidImageDigest(rec.ImageDigest):
		return "the preview has no recorded image digest"
	case !ValidCommitSHA(rec.Revision):
		return "the preview has no source revision"
	}
	return ""
}

// NewPromoteIntent builds the intent for a usable preview record.
func NewPromoteIntent(rec *Record) PromoteIntent {
	return PromoteIntent{
		Kind: PromoteIntentKind, Tenant: rec.Tenant, Service: rec.Service,
		SourceDeploymentID: rec.ID, ImageTag: PromoteTag(rec), ImageDigest: rec.ImageDigest,
	}
}

// CompilePromote returns the production values before and after a promotion:
// image.tag and image.digest set, everything else untouched. A file with no
// image mapping, or with no repository in it, cannot take a promotion.
func CompilePromote(base []byte, in PromoteIntent) (before, after map[string]any, err error) {
	if err := in.validate(); err != nil {
		return nil, nil, err
	}
	before, err = parseValues(base)
	if err != nil {
		return nil, nil, err
	}
	img, ok := before["image"].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: no image mapping", ErrPromoteValues)
	}
	if repo, _ := img["repository"].(string); repo == "" {
		return nil, nil, fmt.Errorf("%w: no image.repository", ErrPromoteValues)
	}
	after = deepCopy(before).(map[string]any)
	ai := after["image"].(map[string]any)
	ai["tag"], ai["digest"] = in.ImageTag, in.ImageDigest
	return before, after, nil
}

// ProductionHost is the host the production values serve, for display: the
// ingress host, else the first of ingress.hosts, else "".
func ProductionHost(values map[string]any) string {
	ing, _ := values["ingress"].(map[string]any)
	if h, _ := ing["host"].(string); h != "" {
		return h
	}
	if hs, _ := ing["hosts"].([]any); len(hs) > 0 {
		switch f := hs[0].(type) {
		case string:
			return f
		case map[string]any:
			h, _ := f["host"].(string)
			return h
		}
	}
	return ""
}
