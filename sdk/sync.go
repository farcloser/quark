package sdk

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/sigstore"
	syncsvc "github.com/farcloser/quark/internal/sync"
)

// SyncArgs contains configuration options for creating a sync operation.
type SyncArgs struct {
	Description string     // Required - operation name
	Source      *Image     // Required - source image (must have digest)
	Destination *Image     // Required - destination image
	Platforms   []Platform // Optional - platforms to sync (default: AMD64, ARM64)
}

// syncOp represents an image sync operation from source to destination registry.
type syncOp struct {
	opName         string
	sourceRegistry *Registry
	sourceImage    *Image
	destRegistry   *Registry
	destImage      *Image
	platforms      []Platform
	trustedSigners []SignerIdentity // Global signers from plan
	log            zerolog.Logger
}

func (op *syncOp) execute(ctx context.Context) error {
	// Apply verification matrix.
	sourceDigest, err := op.verifySource(ctx)
	if err != nil {
		return err
	}

	// Set the verified digest on source image for sync.
	if op.sourceImage.Digest() == "" {
		if err := op.sourceImage.SetDigest(sourceDigest); err != nil {
			return fmt.Errorf("failed to set source digest: %w", err)
		}
	}

	// Use digestRef for source (immutable, secure).
	sourceRef, err := op.sourceImage.digestRef()
	if err != nil {
		return fmt.Errorf("failed to build source reference: %w", err)
	}

	// Use tagRef for destination (includes domain/name:version).
	destRef := op.destImage.tagRef()

	op.log.Info().
		Str("source", sourceRef).
		Str("destination", destRef).
		Msg("syncing image")

	// Create registry clients.
	srcClient := op.createSourceClient()
	dstClient := op.createDestClient()

	// Create syncer and sync.
	syncer := syncsvc.NewSyncer(srcClient, dstClient, op.log)

	destDigest, err := syncer.SyncImage(ctx, sourceRef, destRef)
	if err != nil {
		return fmt.Errorf("failed to sync image: %w", err)
	}

	// Auto-populate destination image digest for subsequent operations.
	if err := op.destImage.SetDigest(destDigest); err != nil {
		return fmt.Errorf("failed to set destination digest: %w", err)
	}

	op.log.Info().
		Str("dest_digest", destDigest).
		Msg("image sync complete")

	return nil
}

// getTrustedIdentities returns the trusted identities to verify against.
// Per-image signedBy takes precedence over global plan signers.
func (op *syncOp) getTrustedIdentities() []SignerIdentity {
	if len(op.sourceImage.signedBy) > 0 {
		return op.sourceImage.signedBy
	}

	return op.trustedSigners
}

// verifySource implements the verification matrix from sigstore.md.
// Returns the verified digest to use for sync.
func (op *syncOp) verifySource(ctx context.Context) (string, error) {
	trustedIdentities := op.getTrustedIdentities()
	insecure := op.sourceImage.insecureNoSignature
	hasTrustPolicy := len(trustedIdentities) > 0

	// Case: No tag and no digest.
	if op.sourceImage.Version() == "" && op.sourceImage.Digest() == "" {
		return "", ErrMustSpecifyTagOrDigest
	}

	// Insecure mode - skip verification but log warning.
	if insecure {
		return op.handleInsecureMode(ctx)
	}

	// Not insecure - trust policy is required.
	if !hasTrustPolicy {
		return "", op.noTrustPolicyError(ctx)
	}

	// Signed verification.
	return op.verifySignature(ctx, trustedIdentities)
}

// noTrustPolicyError builds an actionable error when no trust policy is configured.
// It discovers whether the image is signed and by whom, so the user can decide to trust the signer.
func (op *syncOp) noTrustPolicyError(ctx context.Context) error {
	// Build discovery options.
	discoverOpts := &sigstore.DiscoverSignerOptions{
		ImageRef: op.sourceImage.String(),
		Digest:   op.sourceImage.Digest(),
		Log:      op.log,
	}

	// Add registry auth if available.
	if op.sourceRegistry != nil && op.sourceRegistry.username != "" {
		discoverOpts.RegistryAuth = &sigstore.RegistryAuth{
			Username: op.sourceRegistry.username,
			Password: op.sourceRegistry.token,
		}
	}

	// Discover signer.
	result, err := sigstore.DiscoverSigner(ctx, discoverOpts)
	if err != nil {
		// Discovery failed - return generic error with the discovery error.
		return fmt.Errorf("%w: failed to check signature: %w", ErrNoTrustPolicy, err)
	}

	if !result.IsSigned {
		return fmt.Errorf("%w: image is not signed", ErrNoTrustPolicy)
	}

	// Image is signed - provide actionable error with signer info.
	return fmt.Errorf(
		"%w: image is signed by subject=%q issuer=%q",
		ErrNoTrustPolicy,
		result.Signer.Subject,
		result.Signer.Issuer,
	)
}

// handleInsecureMode handles sync when InsecureNoSignature is true.
func (op *syncOp) handleInsecureMode(ctx context.Context) (string, error) {
	op.log.Warn().
		Str("image", op.sourceImage.String()).
		Msg("INSECURE: Signature verification bypassed (InsecureNoSignature=true)")

	hasTag := op.sourceImage.Version() != ""
	hasDigest := op.sourceImage.Digest() != ""

	// If we have both tag and digest, check for drift.
	if hasTag && hasDigest {
		if err := op.checkTagDrift(ctx); err != nil {
			// Log warning but continue - this is insecure mode.
			op.log.Warn().Err(err).Msg("tag drift detected")
		}

		return op.sourceImage.Digest(), nil
	}

	// If only digest, use it directly.
	if hasDigest {
		return op.sourceImage.Digest(), nil
	}

	// If only tag, resolve to digest.
	return op.resolveTagToDigest(ctx)
}

// verifySignature handles signature verification for signed images.
func (op *syncOp) verifySignature(ctx context.Context, trustedIdentities []SignerIdentity) (string, error) {
	hasTag := op.sourceImage.Version() != ""
	hasDigest := op.sourceImage.Digest() != ""

	// Determine which digest to verify.
	var digestToVerify string

	if hasDigest {
		digestToVerify = op.sourceImage.Digest()
	} else {
		// Resolve tag to get digest.
		resolved, err := op.resolveTagToDigest(ctx)
		if err != nil {
			return "", err
		}

		digestToVerify = resolved
	}

	// Check for tag drift if both specified.
	if hasTag && hasDigest {
		if err := op.checkTagDrift(ctx); err != nil {
			op.log.Warn().Err(err).Msg("tag drift detected")
		}
	}

	// Build verification options.
	verifyOpts := &sigstore.VerifyOptions{
		ImageRef: op.sourceImage.String(),
		Digest:   digestToVerify,
		Log:      op.log,
	}

	// Add registry auth if available.
	if op.sourceRegistry != nil && op.sourceRegistry.username != "" {
		verifyOpts.RegistryAuth = &sigstore.RegistryAuth{
			Username: op.sourceRegistry.username,
			Password: op.sourceRegistry.token,
		}
	}

	// Verify signature cryptographically.
	result, err := sigstore.Verify(ctx, verifyOpts)
	if err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Check if the signer matches any trusted identity.
	trusted := false

	for _, identity := range trustedIdentities {
		if identity.Matches(result.Signer.Subject, result.Signer.Issuer) {
			op.log.Info().
				Str("verified_digest", result.Digest).
				Str("signer_subject", result.Signer.Subject).
				Str("signer_issuer", result.Signer.Issuer).
				Str("matched_pattern", identity.Subject).
				Msg("signature verified - signer trusted")

			trusted = true

			break
		}
	}

	if !trusted {
		return "", fmt.Errorf(
			"%w: signed by subject=%q issuer=%q",
			ErrSignerNotTrusted,
			result.Signer.Subject,
			result.Signer.Issuer,
		)
	}

	return result.Digest, nil
}

// resolveTagToDigest resolves the image tag to a digest via registry API.
func (op *syncOp) resolveTagToDigest(ctx context.Context) (string, error) {
	client := op.createSourceClient()
	tagRef := op.sourceImage.tagRef()

	digest, err := client.GetDigest(ctx, tagRef)
	if err != nil {
		return "", fmt.Errorf("failed to resolve tag to digest: %w", err)
	}

	op.log.Debug().
		Str("tag", tagRef).
		Str("digest", digest).
		Msg("resolved tag to digest")

	return digest, nil
}

// checkTagDrift checks if the current tag points to a different digest than specified.
func (op *syncOp) checkTagDrift(ctx context.Context) error {
	currentDigest, err := op.resolveTagToDigest(ctx)
	if err != nil {
		return fmt.Errorf("failed to check tag drift: %w", err)
	}

	expectedDigest := op.sourceImage.Digest()
	if currentDigest != expectedDigest {
		return fmt.Errorf(
			"%w: tag %q expected %s, got %s",
			ErrTagDrift,
			op.sourceImage.Version(),
			expectedDigest,
			currentDigest,
		)
	}

	return nil
}

// createSourceClient creates a registry client for the source.
func (op *syncOp) createSourceClient() *registry.Client {
	if op.sourceRegistry != nil {
		return registry.NewClient(
			op.sourceRegistry.domain,
			op.sourceRegistry.username,
			op.sourceRegistry.token,
			op.log.With().Str("registry", "source").Logger(),
		)
	}

	return registry.NewClient("", "", "", op.log.With().Str("registry", "source").Logger())
}

// createDestClient creates a registry client for the destination.
func (op *syncOp) createDestClient() *registry.Client {
	if op.destRegistry != nil {
		return registry.NewClient(
			op.destRegistry.domain,
			op.destRegistry.username,
			op.destRegistry.token,
			op.log.With().Str("registry", "destination").Logger(),
		)
	}

	return registry.NewClient("", "", "", op.log.With().Str("registry", "destination").Logger())
}

// operationName returns the sync operation name (implements operation interface).
func (op *syncOp) operationName() string {
	return op.opName
}
