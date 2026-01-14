// Package ssh provides SSH client and connection pool utilities.
//
// The connection pool keys connections by endpoint (host:port) only.
// This means different SSH keys or fingerprints for the same endpoint
// will share the same connection - the one established first.
//
// This design is intentional for single-user CLI tools where connection
// reuse is desired. It is NOT suitable for multi-tenant services where
// different users may need separate authenticated connections to the
// same host.
package ssh
