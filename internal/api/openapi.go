package api

import _ "embed"

// openAPISpec is served from /openapi.yaml. Shipping the specification inside
// the binary means a control plane can generate a client against the exact
// build it is talking to.
//
//go:embed openapi.yaml
var openAPISpec []byte
