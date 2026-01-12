package signature

import (
	_ "embed"

	"github.com/farcloser/quark/internal/signature/sigstore"
	"github.com/farcloser/quark/internal/types"
)

var (
	//go:embed root.json
	trusted string

	//nolint:gochecknoglobals
	// Root is the global trust root for Rekor.
	Root = sigstore.NewRoot(trusted)
)

// NewSigner returns a sigstore concrete implementation of the Signer interface, initialized with the global root.
func NewSigner() types.Signer {
	return sigstore.NewSigner(Root.Get())
}
