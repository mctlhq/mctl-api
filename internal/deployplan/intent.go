package deployplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mctlhq/mctl-api/internal/deployanalyze"
)

// Intent is the typed DeployIntent. It mirrors the closed vendored schema;
// ParseIntent decodes into it with unknown fields refused, as a second guard
// behind the schema validation.
type Intent struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   Metadata   `json:"metadata"`
	Spec       IntentSpec `json:"spec"`
}

// Metadata names the service.
type Metadata struct {
	Tenant  string `json:"tenant"`
	Service string `json:"service"`
}

// IntentSpec is DeployIntent.spec.
type IntentSpec struct {
	Environment string            `json:"environment"`
	Source      Source            `json:"source"`
	Detection   Detection         `json:"detection"`
	Runtime     Runtime           `json:"runtime"`
	Resources   *Resources        `json:"resources,omitempty"`
	Exposure    Exposure          `json:"exposure"`
	Env         map[string]string `json:"env,omitempty"`
	SecretRefs  []SecretRef       `json:"secretRefs,omitempty"`
}

// Source is the repository and pinned revision.
type Source struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
	Dockerfile string `json:"dockerfile"`
	Context    string `json:"context"`
}

// Detection is the analysis tier.
type Detection struct {
	Tier string `json:"tier"`
}

// Runtime is the container runtime shape.
type Runtime struct {
	Port       int    `json:"port"`
	HealthPath string `json:"healthPath"`
	Replicas   int    `json:"replicas"`
}

// Resources are Kubernetes requests and limits.
type Resources struct {
	Requests ResourceSet `json:"requests"`
	Limits   ResourceSet `json:"limits"`
}

// ResourceSet is cpu and memory.
type ResourceSet struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

// Exposure is how the service is reachable.
type Exposure struct {
	Mode string `json:"mode"`
}

// SecretRef names an env var fed from a property of the derived Vault secret.
type SecretRef struct {
	Env      string `json:"env"`
	Property string `json:"property"`
}

// ParseIntent validates raw against the vendored schema and returns the typed
// intent and its canonical JSON: sorted keys, no insignificant whitespace,
// schema defaults (dockerfile, context, replicas) made explicit, so that an
// omitted default and a spelled-out one digest identically.
func ParseIntent(raw []byte) (Intent, []byte, error) {
	var zero Intent
	if err := rejectDuplicateKeys(raw); err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentInvalid, err)
	}
	if err := ensureEOF(dec); err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentInvalid, err)
	}
	if err := deployanalyze.Validate(generic); err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentInvalid, err)
	}

	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	var in Intent
	if err := typed.Decode(&in); err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentInvalid, err)
	}
	if in.Spec.Source.Dockerfile == "" {
		in.Spec.Source.Dockerfile = "Dockerfile"
	}
	if in.Spec.Source.Context == "" {
		in.Spec.Source.Context = "."
	}
	if in.Spec.Runtime.Replicas == 0 {
		in.Spec.Runtime.Replicas = 1
	}

	canon, err := canonicalJSON(in)
	if err != nil {
		return zero, nil, err
	}
	return in, canon, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// canonicalJSON marshals v through a generic value so map keys are sorted.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing intent: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonicalizing intent: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, fmt.Errorf("canonicalizing intent: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// rejectDuplicateKeys refuses a JSON document in which any object repeats a
// key: encoding/json would silently keep the last one.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSON(dec); err != nil {
		return err
	}
	return nil
}

func walkJSON(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err := walkJSON(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}
