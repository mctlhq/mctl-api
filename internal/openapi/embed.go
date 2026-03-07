package openapi

import _ "embed"

// Spec is the OpenAPI 3.0 specification for the mctl REST API.
//
//go:embed openapi.yaml
var Spec []byte
