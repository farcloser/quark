package trust

import "errors"

// CA trust errors.
var (
	// ErrNoCertificates indicates no valid certificates were found in the provided PEM data.
	ErrNoCertificates = errors.New("no valid certificates found in PEM data")
	// ErrReadCertificate indicates failure reading a certificate file.
	ErrReadCertificate = errors.New("failed to read certificate file")
)

// Key generation errors.
var (
	// ErrKeyGeneration indicates key generation failed.
	ErrKeyGeneration = errors.New("key generation failed")

	// ErrKeyEncryption indicates key encryption failed.
	ErrKeyEncryption = errors.New("key encryption failed")
)
