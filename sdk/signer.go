package sdk

import (
	"github.com/farcloser/quark/dev/resource"
)

// Signer represents a signing configuration.
type Signer struct {
	resource.BaseResource[Signer]

	opts SignerOpts
}

// SignerOpts contains configuration options for creating a signer.
type SignerOpts struct {
	// Keyless OIDC
	OIDCIssuer string
	OIDCToken  string
	// Key-based
	PrivateKey  []byte
	KeyPassword []byte
}

// NewSigner creates a new Signer with the given options.
func NewSigner(opts SignerOpts) *Signer {
	s := &Signer{
		opts: opts,
	}
	s.BaseResource = resource.NewBaseResource(s, "signer")

	return s
}
