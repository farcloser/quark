package attest

// Statement represents a VEX statement for attesting vulnerability exploitability.
type Statement struct {
	Vulnerability string // CVE ID (e.g., "CVE-2025-61729")
	Product       string // Package URL (e.g., "pkg:golang/stdlib@v1.25.4")
	Justification string // Why the vulnerability doesn't apply (e.g., "vulnerable_code_not_in_execute_path")
}

// Options configures attestation behavior.
type Options struct {
	// Files are local VEX files to attach (OpenVEX, CSAF, or CycloneDX format).
	Files []string

	// Statements are inline VEX statements for suppressing vulnerabilities.
	Statements []*Statement

	// DisableTransparencyLog skips uploading the attestation to Rekor.
	// Default: false (attestations are published to transparency log).
	DisableTransparencyLog bool
}
