package api

import (
	"bytes"
	_ "embed"
)

// The existing specification and the bounded setup path extension are kept
// separately to make the new surface reviewable. The served /openapi.yaml is
// one complete document for the exact binary, never a remote reference.
//
//go:embed openapi.yaml
var baseOpenAPISpec []byte

//go:embed openapi-setup.yaml
var setupOpenAPIPaths []byte

var openAPISpec = withAccessActivitySchema(combinedOpenAPISpec(baseOpenAPISpec, setupOpenAPIPaths))

func combinedOpenAPISpec(base, extra []byte) []byte {
	marker := []byte("\npaths:\n")
	if bytes.Count(base, marker) != 1 {
		panic("api: OpenAPI document must contain exactly one paths mapping")
	}
	insertion := bytes.Join([][]byte{marker, extra}, nil)
	return bytes.Replace(base, marker, insertion, 1)
}
