package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	sigstore2 "github.com/farcloser/quark/internal/a_deprecated/sigstore"
	"github.com/farcloser/quark/sdk/attest"
)

type attestAction struct {
	*resource.BaseAction

	opts   *attest.Options
	output *Image
	signer *Signer
}

func (aa *attestAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(aa, aa.BaseAction, name, out, copyFrom...)
}

func (aa *attestAction) Execute(ctx context.Context) error {
	output := aa.output

	// Attest requires digest for deterministic attestation
	if output.ref.Digest == "" {
		return fmt.Errorf("%w: %s", attest.ErrNoStatements, output.ref.String())
	}

	// Signer is required
	if aa.signer == nil {
		return fmt.Errorf("%w: signer is required", attest.ErrNoStatements)
	}

	if aa.opts == nil {
		aa.opts = &attest.Options{}
	}

	// Create registry client for pushing the attestation
	regClient := registry.NewClient(output.registry.credentials(), output.log)

	// Build sigstore attest options
	attestOpts := &sigstore2.AttestOptions{
		ImageRef:                 *output.ref,
		Digest:                   output.ref.Digest.String(),
		OIDCIssuer:               aa.signer.options.OIDCIssuer,
		OIDCToken:                aa.signer.options.OIDCToken,
		PrivateKey:               aa.signer.options.PrivateKey,
		KeyPassword:              string(aa.signer.options.KeyPassword),
		RegistryClient:           regClient,
		PublishToTransparencyLog: !aa.opts.DisableTransparencyLog,
		Files:                    aa.opts.Files,
		Statements:               aa.opts.Statements,
		Log:                      output.log,
	}

	if err := sigstore2.Attest(ctx, attestOpts); err != nil {
		return fmt.Errorf("%w: %w", sigstore2.ErrAttestFailed, err)
	}

	output.log.InfoContext(ctx, "image attested successfully",
		slog.String("image", output.ref.String()),
		slog.Bool("keyless", aa.signer.options.OIDCToken != ""),
		slog.Bool("tlog", !aa.opts.DisableTransparencyLog),
		slog.Int("statements", len(aa.opts.Statements)),
		slog.Int("files", len(aa.opts.Files)))

	return nil
}
