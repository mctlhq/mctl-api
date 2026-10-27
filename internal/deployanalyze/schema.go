// Package deployanalyze statically analyzes a GitHub repository at a pinned
// commit and answers whether it can be deployed as-is (Tier 0: a Dockerfile),
// as a schema-valid draft DeployIntent or a reasoned Unsupported verdict.
// It never clones, builds or runs anything.
package deployanalyze

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaSHA256 pins the vendored DeployIntent schema.
const SchemaSHA256 = "cd2e6f1d6dd07a47b878b54ebc47999aafb1890a77a140ccc74b400429e386c4"

// SchemaSource is where the vendored schema is copied from.
const SchemaSource = "mctlhq/mctl-gitops:platform-gitops/agent-platform/schemas/deploy-intent.schema.json"

//go:embed schema/deploy-intent.schema.json
var schemaBytes []byte

var (
	schemaOnce     sync.Once
	compiledSchema *jsonschema.Schema
	schemaErr      error
)

func compile() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			schemaErr = fmt.Errorf("parsing vendored schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		const url = "https://mctl.ai/schemas/deploy/v1alpha1/deploy-intent.schema.json"
		if err := c.AddResource(url, doc); err != nil {
			schemaErr = fmt.Errorf("adding vendored schema: %w", err)
			return
		}
		compiledSchema, schemaErr = c.Compile(url)
		if schemaErr != nil {
			schemaErr = fmt.Errorf("compiling vendored schema: %w", schemaErr)
		}
	})
	return compiledSchema, schemaErr
}

// Validate checks draft against the vendored DeployIntent schema.
func Validate(draft map[string]any) error {
	s, err := compile()
	if err != nil {
		return err
	}
	// Round-trip through JSON so numbers and nested types are what the
	// validator expects.
	raw, err := json.Marshal(draft)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}
