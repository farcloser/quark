package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/a_deprecated/sigstore"
	"github.com/farcloser/quark/sdk/sign"
)

type signAction struct {
	*resource.BaseAction

	opts   *sign.Options
	output *Image
	signer *Signer
}

func (sa *signAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(sa, sa.BaseAction, name, out, copyFrom...)
}

func (sa *signAction) Execute(ctx context.Context) error {
	output := sa.output

	// Sign requires digest for deterministic signing
	if output.ref.Digest == "" {
		return fmt.Errorf("%w: %s", sign.ErrArgumentRequiredImageDigest, output.ref.String())
	}

	// Signer is required
	if sa.signer == nil {
		return sign.ErrArgumentRequiredSigner
	}

	if sa.opts == nil {
		sa.opts = &sign.Options{}
	}

	// Create registry client for pushing the signature
	regClient := registry.NewClient(output.registry.credentials(), output.log)

	// Build sigstore sign options
	signOpts := &sigstore.SignOptions{
		ImageRef:                 *output.ref,
		Digest:                   output.ref.Digest.String(),
		OIDCIssuer:               sa.signer.options.OIDCIssuer,
		OIDCToken:                sa.signer.options.OIDCToken,
		PrivateKey:               sa.signer.options.PrivateKey,
		KeyPassword:              string(sa.signer.options.KeyPassword),
		PublishToTransparencyLog: !sa.opts.DisableTransparencyLog,
		Annotations:              sa.opts.Annotations,
		RegistryClient:           regClient,
		Log:                      output.log,
	}

	if err := sigstore.Sign(ctx, signOpts); err != nil {
		return fmt.Errorf("%w: %w", sign.ErrSigningFailed, err)
	}

	output.log.InfoContext(ctx, "image signed successfully",
		slog.String("image", output.ref.String()),
		slog.Bool("keyless", sa.signer.options.OIDCToken != ""),
		slog.Bool("tlog", !sa.opts.DisableTransparencyLog))

	return nil
}
