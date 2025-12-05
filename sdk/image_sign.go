package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/sigstore"
	"github.com/farcloser/quark/sdk/sign"
)

type signAction struct {
	resource.BaseResource[signAction]
	log    *slog.Logger
	opts   *sign.Options
	image  *Image
	signer *Signer
}

func (sa *signAction) Execute(ctx context.Context) error {
	// Sign requires digest for deterministic signing
	if sa.image.ref.Digest == "" {
		return fmt.Errorf("%w: %s", sign.ErrArgumentRequiredImageDigest, sa.image.ref.String())
	}

	// Signer is required
	if sa.signer == nil {
		return sign.ErrArgumentRequiredSigner
	}

	if sa.opts == nil {
		sa.opts = &sign.Options{}
	}

	// Create registry client for pushing the signature
	regClient := registry.NewClient(sa.image.registry.credentials(), sa.log)

	// Build sigstore sign options
	signOpts := &sigstore.SignOptions{
		ImageRef:                 *sa.image.ref,
		Digest:                   sa.image.ref.Digest.String(),
		OIDCIssuer:               sa.signer.opts.OIDCIssuer,
		OIDCToken:                sa.signer.opts.OIDCToken,
		PrivateKey:               sa.signer.opts.PrivateKey,
		KeyPassword:              string(sa.signer.opts.KeyPassword),
		PublishToTransparencyLog: !sa.opts.DisableTransparencyLog,
		Annotations:              sa.opts.Annotations,
		RegistryClient:           regClient,
		Log:                      sa.log,
	}

	if err := sigstore.Sign(ctx, signOpts); err != nil {
		return fmt.Errorf("%w: %w", sign.ErrSigningFailed, err)
	}

	sa.log.InfoContext(ctx, "image signed successfully",
		slog.String("image", sa.image.ref.String()),
		slog.Bool("keyless", sa.signer.opts.OIDCToken != ""),
		slog.Bool("tlog", !sa.opts.DisableTransparencyLog))

	return nil
}
