package sign

// Options configures image signing behavior.
type Options struct {
	// Annotations are custom key-value pairs to attach to the signature.
	Annotations map[string]string

	// DisableTransparencyLog skips uploading the signature to Rekor.
	// Default: false (signatures are published to transparency log).
	DisableTransparencyLog bool
}
