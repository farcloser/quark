// Package sarif provides Go types for the SARIF (Static Analysis Results Interchange Format) 2.1.0 schema.
// Types are generated from the official OASIS SARIF JSON Schema.
//
// Schema source: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
//
//go:generate go-jsonschema -p sarif -o sarif.go sarif-schema-2.1.0.json
package sarif
