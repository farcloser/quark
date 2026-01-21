package signature

import (
	_ "embed"

	"github.com/farcloser/quark/internal/types"
	sigstore2 "github.com/farcloser/quark/pkg/sys/signature/sigstore"
)

var (
	//go:embed root.json
	trusted string

	//nolint:gochecknoglobals
	// Root is the global trust root for Rekor.
	Root = sigstore2.NewRoot(trusted)
)

// NewSigner returns a sigstore concrete implementation of the Signer interface, initialized with the global root.
func NewSigner() types.Signer {
	return sigstore2.NewSigner(Root.Get())
}
