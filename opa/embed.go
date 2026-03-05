package opa

import _ "embed"

//go:embed authz.rego
var AuthzRego []byte
