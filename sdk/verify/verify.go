package verify

// Options configures signature verification behavior.
type Options struct {
	// TrustedKeyless specifies which signers are trusted.
	// For keyless: map of issuer -> subject regex (e.g., {"https://accounts.google.com": ".*@example.com"})
	// For key-based: ignored (trust is implicit in providing the public key)
	TrustedKeyless map[string]string

	// TrustedKeys is the PEM-encoded public key for key-based verification.
	// If provided, performs key-based verification instead of keyless.
	TrustedKeys []byte

	// DisableTransparencyLog skips checking the Rekor transparency log.
	// Default: false (transparency log is checked).
	DisableTransparencyLog bool

	// InsecureTrustDigest practically bypasses a signature verification error on an image that has a digest.
	// Useful to trust an image by digest that has been vetted out of band
	InsecureTrustDigest bool

	// InsecureTrustBlindly practically bypasses all verification.
	// You are on your own.
	InsecureTrustBlindly bool
}
