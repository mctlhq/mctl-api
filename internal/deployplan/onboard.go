package deployplan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

// ErrOnboardNotReproducible means the values a stored onboard plan binds
// cannot be rebuilt from its intent, so it must not be applied.
var ErrOnboardNotReproducible = errors.New("the plan's values cannot be reproduced from its intent")

// maxCompiledValuesB64 is the cap wft-preview-deploy enforces on the
// compiled_values parameter.
const maxCompiledValuesB64 = 96000

var imageRepoRe = regexp.MustCompile(`^ghcr\.io/[a-z0-9][a-z0-9-]{0,38}/[a-z0-9][a-z0-9-]{0,30}$`)

// OnboardBase is the platform-set part of the values of a service that has
// no values.yaml in gitops yet: the repository of the image the platform
// builds from source and the registry pull secret. Everything else comes
// from the intent (applyIntent) or the preview overrides, never from a
// caller (deploy-intent-chart-keys.yaml, "platform").
func OnboardBase(service, org string) (map[string]any, string, error) {
	repo := "ghcr.io/" + org + "/" + service
	if !imageRepoRe.MatchString(repo) {
		return nil, "", fmt.Errorf("%w: %q is not an image repository", ErrOnboardNotReproducible, repo)
	}
	return map[string]any{
		"image":            map[string]any{"repository": repo},
		"imagePullSecrets": []any{map[string]any{"name": "ghcr-credentials"}},
	}, repo, nil
}

// CompileOnboardPreview is CompilePreview over OnboardBase: before is what
// the platform base alone would deploy, after is the same with the intent.
func CompileOnboardPreview(in Intent, org, previewID, host string) (before, after map[string]any, err error) {
	base, _, err := OnboardBase(in.Metadata.Service, org)
	if err != nil {
		return nil, nil, err
	}
	rendered, err := RenderYAML(base)
	if err != nil {
		return nil, nil, err
	}
	return CompilePreview([]byte(rendered), in, previewID, host)
}

// CompiledValues is what preview-deploy receives for an onboard plan: the
// unredacted values of after, rendered canonically, gzip then base64, and the
// sha256 of the rendering. The workflow recomputes the hash before using
// them.
func CompiledValues(after map[string]any) (b64, sha string, err error) {
	rendered, err := RenderYAML(after)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(rendered)); err != nil {
		return "", "", fmt.Errorf("compressing values: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", "", fmt.Errorf("compressing values: %w", err)
	}
	b64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	if len(b64) > maxCompiledValuesB64 {
		return "", "", fmt.Errorf("%w: the compiled values are over %d characters", ErrOnboardNotReproducible, maxCompiledValuesB64)
	}
	return b64, SHA256Hex(rendered), nil
}

// OnboardValuesForPlan rebuilds the values an onboard plan binds and returns
// them ready for preview-deploy. It refuses unless the redacted rendering of
// what it rebuilt is exactly the plan's ValuesAfter, so what is deployed is
// what was approved, even if the compiler changed since the plan was made.
func OnboardValuesForPlan(p *Plan, in Intent, org string) (b64, sha string, err error) {
	_, after, err := CompileOnboardPreview(in, org, p.PreviewID, p.Host)
	if err != nil {
		return "", "", err
	}
	redacted, err := RenderYAML(Redact(after))
	if err != nil {
		return "", "", err
	}
	if redacted != p.ValuesAfter {
		return "", "", fmt.Errorf("%w: the rebuilt values differ from the approved ones", ErrOnboardNotReproducible)
	}
	return CompiledValues(after)
}
