package sdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	sigstore2 "github.com/farcloser/quark/internal/a_deprecated/sigstore"
	"github.com/farcloser/quark/internal/types"
)

// ErrGetDigest indicates failure to retrieve image digest from registry.
var ErrGetDigest = errors.New("failed to get image digest")

type syncMetadataAction struct {
	*resource.BaseAction

	output *Image
}

func (sa *syncMetadataAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(sa, sa.BaseAction, name, out, copyFrom...)
}

func (sa *syncMetadataAction) Execute(ctx context.Context) error {
	output := sa.output

	// Create registry client
	regClient := registry.NewClient(output.registry.credentials(), output.log)

	// Resolve digest if not provided
	if output.ref.Digest == "" {
		dgst, err := regClient.GetDigest(ctx, *output.ref)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrGetDigest, err)
		}

		output.ref.Digest = types.Digest(dgst)
		output.log.DebugContext(ctx, "resolved image digest", "digest", dgst)
	}

	// Inspect signature information (don't fail if not signed)
	sa.inspectSignature(ctx, regClient)

	// Inspect attestations (don't fail if none found)
	sa.inspectAttestations(ctx, regClient)

	return nil
}

// inspectSignature retrieves signature information for the image without verification.
// If the image is not signed, it logs a debug message but does not error.
func (sa *syncMetadataAction) inspectSignature(ctx context.Context, regClient *registry.Client) {
	output := sa.output

	result, err := sigstore2.Inspect(ctx, &sigstore2.InspectOptions{
		ImageRef:       *output.ref,
		Digest:         output.ref.Digest.String(),
		RegistryClient: regClient,
		Log:            output.log,
	})
	if err != nil {
		output.log.DebugContext(ctx, "failed to inspect signature",
			slog.String("image", output.ref.String()),
			slog.String("reason", err.Error()))

		// Store empty result indicating no signature
		output.signatureInfo = &sigstore2.InspectResult{
			IsSigned: false,
			Digest:   output.ref.Digest.String(),
		}

		return
	}

	output.signatureInfo = result

	if result.IsSigned {
		if result.Keyless != nil {
			output.log.InfoContext(ctx, "keyless signature found",
				slog.String("image", output.ref.String()),
				slog.String("issuer", result.Keyless.Issuer),
				slog.String("subject", result.Keyless.Subject))
		} else if result.IsKeyBased {
			output.log.InfoContext(ctx, "key-based signature found",
				slog.String("image", output.ref.String()),
				slog.String("digest", result.Digest))
		}
	} else {
		output.log.DebugContext(ctx, "image is not signed",
			slog.String("image", output.ref.String()))
	}
}

// inspectAttestations retrieves attestation information for the image.
// If no attestations are found, it logs a debug message but does not error.
func (sa *syncMetadataAction) inspectAttestations(ctx context.Context, regClient *registry.Client) {
	output := sa.output

	result, err := sigstore2.InspectAttestations(ctx, &sigstore2.InspectAttestationsOptions{
		ImageRef:       *output.ref,
		Digest:         output.ref.Digest.String(),
		RegistryClient: regClient,
		Log:            output.log,
	})
	if err != nil {
		output.log.DebugContext(ctx, "failed to inspect attestations",
			slog.String("image", output.ref.String()),
			slog.String("reason", err.Error()))

		// Store empty result indicating no attestations
		output.attestationsInfo = &sigstore2.AttestationsResult{
			HasAttestations: false,
			Digest:          output.ref.Digest.String(),
		}

		return
	}

	output.attestationsInfo = result

	if result.HasAttestations {
		output.log.InfoContext(ctx, "attestations found",
			slog.String("image", output.ref.String()),
			slog.Int("count", len(result.Attestations)))

		for idx, att := range result.Attestations {
			switch {
			case att.Keyless != nil:
				output.log.DebugContext(ctx, "keyless attestation",
					slog.Int("index", idx),
					slog.String("predicateType", att.PredicateType),
					slog.String("issuer", att.Keyless.Issuer),
					slog.String("subject", att.Keyless.Subject))
			case att.IsKeyBased:
				output.log.DebugContext(ctx, "key-based attestation",
					slog.Int("index", idx),
					slog.String("predicateType", att.PredicateType))
			default:
				output.log.DebugContext(ctx, "unsigned attestation",
					slog.Int("index", idx),
					slog.String("predicateType", att.PredicateType))
			}
		}
	} else {
		output.log.DebugContext(ctx, "no attestations found",
			slog.String("image", output.ref.String()))
	}
}
