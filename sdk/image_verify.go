package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/sigstore"
	"github.com/farcloser/quark/sdk/verify"
)

type verifyAction struct {
	resource.BaseResource[verifyAction]

	log    *slog.Logger
	opts   *verify.Options
	image  *Image
	result *sigstore.VerificationResult
}

func (va *verifyAction) Execute(ctx context.Context) error {
	providedDigest := va.image.ref.Digest
	// Resolve digest if not provided (allows verifying by tag)
	if va.image.ref.Digest == "" {
		regClient := registry.NewClient(va.image.registry.credentials(), va.log)

		dgst, err := regClient.GetDigest(ctx, *va.image.ref)
		if err != nil {
			return fmt.Errorf("%w: %w", verify.ErrGetDigest, err)
		}

		va.image.ref.Digest = reference.Digest(dgst)
		va.log.DebugContext(ctx, "resolved image digest", "digest", dgst)
	}

	if va.opts == nil {
		va.opts = &verify.Options{}
	}

	// Determine verification mode: key-based or keyless
	var err error
	if len(va.opts.TrustedKeys) > 0 {
		err = va.verifyWithKey(ctx)
	} else {
		err = va.verifyKeyless(ctx)
	}

	if err != nil {
		if providedDigest != "" && va.opts.InsecureTrustDigest {
			va.log.WarnContext(ctx, "signature verification failed (insecure mode - continuing)",
				slog.String("image", va.image.ref.String()),
				slog.String("error", err.Error()))

			return nil
		}

		if va.opts.InsecureTrustBlindly {
			va.log.WarnContext(
				ctx,
				"DANGER: signature verification failed and no digest was provide (insecure mode - continuing)",
				slog.String("image", va.image.ref.String()),
				slog.String("error", err.Error()),
			)

			return nil
		}

		return err
	}

	return nil
}

// verifyKeyless performs keyless (Fulcio) signature verification.
func (va *verifyAction) verifyKeyless(ctx context.Context) error {
	// Keyless verification requires trusted identities
	if len(va.opts.TrustedKeyless) == 0 {
		return verify.ErrNoTrustedIdentities
	}

	// Create registry client for fetching signature artifacts
	regClient := registry.NewClient(va.image.registry.credentials(), va.log)

	result, err := sigstore.Verify(ctx, &sigstore.VerifyOptions{
		ImageRef:       *va.image.ref,
		Digest:         va.image.ref.Digest.String(),
		RegistryClient: regClient,
		Log:            va.log,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", verify.ErrSignatureVerificationFailed, err)
	}

	// Check if signer is trusted
	if result.Keyless == nil {
		return fmt.Errorf("%w: signature is not keyless", verify.ErrSignerNotTrusted)
	}

	if !va.isSignerTrusted(result.Keyless) {
		return fmt.Errorf("%w: issuer=%s subject=%s",
			verify.ErrSignerNotTrusted,
			result.Keyless.Issuer,
			result.Keyless.Subject)
	}

	va.log.InfoContext(ctx, "signature verified",
		slog.String("image", va.image.ref.String()),
		slog.String("issuer", result.Keyless.Issuer),
		slog.String("subject", result.Keyless.Subject))

	va.result = result

	return nil
}

// verifyWithKey performs key-based signature verification.
func (va *verifyAction) verifyWithKey(ctx context.Context) error {
	// Create registry client for fetching signature artifacts
	regClient := registry.NewClient(va.image.registry.credentials(), va.log)

	result, err := sigstore.VerifyWithPublicKey(ctx, &sigstore.VerifyWithKeyOptions{
		ImageRef:       *va.image.ref,
		Digest:         va.image.ref.Digest.String(),
		PublicKey:      va.opts.TrustedKeys,
		RegistryClient: regClient,
		Log:            va.log,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", verify.ErrSignatureVerificationFailed, err)
	}

	va.log.InfoContext(ctx, "key-based signature verified",
		slog.String("image", va.image.ref.String()),
		slog.String("digest", result.Digest))

	va.result = result

	return nil
}

// isSignerTrusted checks if the signer matches any trusted identity.
func (va *verifyAction) isSignerTrusted(keyless *sigstore.KeylessSignerInfo) bool {
	for issuer, subjectPattern := range va.opts.TrustedKeyless {
		if keyless.Issuer != issuer {
			continue
		}

		matched, err := regexp.MatchString(subjectPattern, keyless.Subject)
		if err != nil {
			va.log.Warn("invalid subject regex pattern",
				slog.String("pattern", subjectPattern),
				slog.String("error", err.Error()))

			continue
		}

		if matched {
			return true
		}
	}

	return false
}
