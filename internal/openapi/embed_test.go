package openapi

import (
	"strings"
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
		"/api/v1/work-items":                     {"get", "post"},
		"/api/v1/work-items/{id}":                {"get", "patch"},
		"/api/v1/work-items/{id}/intents":        {"post"},
		"/api/v1/work-items/{id}/executions":     {"get", "post"},
		"/api/v1/work-items/{id}/resume":         {"post"},
		"/api/v1/work-items/{id}/surface-refs":   {"post"},
		"/api/v1/work-items/{id}/events":         {"get"},
		"/api/v1/action-approvals":               {"get", "post"},
		"/api/v1/action-approvals/{id}":          {"get"},
		"/api/v1/action-approvals/{id}/decision": {"post"},
		"/api/v1/action-approvals/{id}/consume":  {"post"},
	} {
		for _, m := range methods {
			if _, ok := doc.Paths[path][m]; !ok {
				t.Errorf("%s %s is routed but not documented", m, path)
			}
		}
	}
}

// JSON Schema evaluates additionalProperties per allOf branch, so a closed
// schema composed with a sibling that adds properties accepts no body at
// all. Every request body must avoid that shape.
func TestNoRequestBodyComposesAClosedSchema(t *testing.T) {
	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatal(err)
	}
	resolve := func(s map[string]any) map[string]any {
		if ref, ok := s["$ref"].(string); ok {
			return doc.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
		}
		return s
	}
	for path, methods := range doc.Paths {
		for method, op := range methods {
			opm, _ := op.(map[string]any)
			rb, _ := opm["requestBody"].(map[string]any)
			content, _ := rb["content"].(map[string]any)
			for _, media := range content {
				mm, _ := media.(map[string]any)
				schema, _ := mm["schema"].(map[string]any)
				branches, _ := resolve(schema)["allOf"].([]any)
				if len(branches) < 2 {
					continue
				}
				for _, b := range branches {
					bm, _ := b.(map[string]any)
					if resolve(bm)["additionalProperties"] == false {
						t.Errorf("%s %s: allOf composes a closed schema; no body can satisfy it", method, path)
					}
				}
			}
		}
	}
}

// The wave execute schema is exactly the handler's body.
func TestRoadmapWaveExecuteSchemaMatchesTheBody(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
				Closed     any            `yaml:"additionalProperties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Components.Schemas["RoadmapWaveExecuteRequest"]
	for _, k := range []string{"epic", "required_only", "items", "plan_hash", "state_revision"} {
		if _, ok := s.Properties[k]; !ok {
			t.Errorf("RoadmapWaveExecuteRequest lacks %s", k)
		}
	}
	if len(s.Properties) != 5 || s.Closed != false || len(s.Required) != 4 {
		t.Errorf("RoadmapWaveExecuteRequest = %+v", s)
	}
}
