package sdk

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
)

// Signer represents a signing configuration.
type Signer struct {
	resource.Resource

	options SignerOpts
	log     *slog.Logger
}

// SignerOpts contains configuration options for creating a signer.
type SignerOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker string
	// Keyless OIDC
	OIDCIssuer string
	OIDCToken  string
	// Key-based
	PrivateKey  []byte
	KeyPassword []byte
}

// NewSigner creates a new Signer with the given options.
func NewSigner(opts SignerOpts) *Signer {
	moniker := opts.Moniker
	if moniker == "" {
		moniker = "unnamed"
	}

	output := &Signer{
		options: opts,
		log:     slog.With(signerResourceName, moniker),
	}

	moniker = fmt.Sprintf("%s:%s", signerResourceName, moniker)

	output.Resource = (&createSignerAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker)),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}
