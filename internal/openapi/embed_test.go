package openapi

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The spec is served verbatim at /openapi.yaml. A YAML error there (an
// unquoted ": " in a description once shipped one) breaks every client
// generator and doc viewer, and nothing else would notice.
func TestSpecParses(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	for path, methods := range map[string][]string{
		"/api/v1/work-items":                   {"get", "post"},
		"/api/v1/work-items/{id}":              {"get", "patch"},
		"/api/v1/work-items/{id}/intents":      {"post"},
		"/api/v1/work-items/{id}/executions":   {"get", "post"},
		"/api/v1/work-items/{id}/resume":       {"post"},
		"/api/v1/work-items/{id}/surface-refs": {"post"},
		"/api/v1/work-items/{id}/events":       {"get"},
	} {
		for _, m := range methods {
			if _, ok := doc.Paths[path][m]; !ok {
				t.Errorf("%s %s is routed but not documented", m, path)
			}
		}
	}
}
