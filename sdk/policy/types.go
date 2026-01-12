package policy

import (
	devpolicy "github.com/farcloser/quark/dev/policy"
)

// Re-export core types from dev/policy for convenience.
type (
	// Policy evaluates an input and returns a result.
	Policy = devpolicy.Policy

	// Result is returned by policy evaluation.
	Result = devpolicy.Result

	// Verdict represents the outcome of policy evaluation.
	Verdict = devpolicy.Verdict
)

// Re-export verdict constants.
//
//nolint:gochecknoglobals // Verdict enum pattern requires global variables
var (
	Allow = devpolicy.Allow
	Deny  = devpolicy.Deny
	Warn  = devpolicy.Warn
	Skip  = devpolicy.Skip
)

// Re-export combinators.
//
//nolint:gochecknoglobals // Combinator exports require global variables
var (
	// All requires all policies to allow (AND logic).
	All = devpolicy.All
	// Any requires at least one policy to allow (OR logic).
	Any = devpolicy.Any
)

// ImageInput is the policy input for image-based checks.
// It contains a snapshot of the image state at the time of policy evaluation.
type ImageInput struct {
	// Image identification
	Reference string // Full image reference (e.g., "ghcr.io/org/app:v1@sha256:...")
	Digest    string // Image digest (e.g., "sha256:abc123...")
	Domain    string // Registry domain (e.g., "ghcr.io")
	Name      string // Image name/path (e.g., "org/app")
	Tag       string // Image tag (e.g., "v1")

	// Optional - populated if Scan() was in the chain before Check()
	Scan *ScanInput

	// Optional - populated if Audit() was in the chain before Check()
	Audit *AuditInput

	// Optional - populated if Sync() was in the chain before Check()
	Signature *SignatureInput
}

// ScanInput contains vulnerability scan results.
type ScanInput struct {
	Critical int // Count of critical severity vulnerabilities
	High     int // Count of high severity vulnerabilities
	Medium   int // Count of medium severity vulnerabilities
	Low      int // Count of low severity vulnerabilities
	Unknown  int // Count of unknown severity vulnerabilities
}

// AuditInput contains image audit results.
type AuditInput struct {
	Fatal int // Count of fatal level issues
	Warn  int // Count of warning level issues
	Info  int // Count of info level issues
}

// SignatureInput contains signature inspection results.
type SignatureInput struct {
	Signed     bool   // Whether the image has a signature
	IsKeyBased bool   // True if signature is key-based (not keyless/Fulcio)
	Issuer     string // OIDC issuer (for keyless signatures only)
	Subject    string // OIDC subject (for keyless signatures only)
}

// BuilderInput is the policy input for builder-based checks.
// It contains a snapshot of the builder state at the time of policy evaluation.
type BuilderInput struct {
	// Builder identification
	Dockerfile string // Path to the Dockerfile
	Context    string // Build context path

	// Optional - populated if Lint() was in the chain before Check()
	Lint *LintInput
}

// LintInput contains Dockerfile lint results.
type LintInput struct {
	Error   int // Count of error severity issues
	Warning int // Count of warning severity issues
	Info    int // Count of info severity issues
	Style   int // Count of style severity issues
}
