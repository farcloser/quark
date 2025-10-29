package sdk

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/version"
)

// VersionCheck represents a version check operation.
type VersionCheck struct {
	opName   string
	image    *Image
	registry *Registry
	log      zerolog.Logger

	// Results populated after execution
	currentVersion  string
	latestVersion   string
	latestDigest    string
	updateAvailable bool
	executed        bool
}

// VersionCheckBuilder builds a VersionCheck.
type VersionCheckBuilder struct {
	plan  *Plan
	check *VersionCheck
}

// Source sets the source image.
// The image must have a version specified. Digest is optional:
// - If digest is provided: verifies the version tag points to expected digest (fails on mismatch)
// - If digest is not provided: shows warning with actual digest
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found, anonymous access will be used (public repos only).
func (builder *VersionCheckBuilder) Source(image *Image) *VersionCheckBuilder {
	builder.check.image = image
	builder.check.registry = builder.plan.getRegistry(image.domain)

	return builder
}

// Build validates and adds the version check to the plan.
func (builder *VersionCheckBuilder) Build() (*VersionCheck, error) {
	if builder.check.image == nil {
		return nil, ErrVersionCheckImageRequired
	}

	if builder.check.image.version == "" {
		return nil, ErrVersionCheckVersionRequired
	}

	builder.plan.versionChecks = append(builder.plan.versionChecks, builder.check)
	builder.plan.operations = append(builder.plan.operations, builder.check)

	return builder.check, nil
}

func (check *VersionCheck) execute(_ context.Context) error {
	img := check.image

	check.log.Info().
		Str("image", img.name).
		Str("version", img.version).
		Msg("checking for version updates")

	// Create version checker with optional registry credentials
	var username, password string
	if check.registry != nil {
		username = check.registry.username
		password = check.registry.password
	}

	checker := version.NewChecker(username, password, check.log)

	// Use tagRef to query what the tag points to
	tagReference, err := img.tagRef()
	if err != nil {
		return fmt.Errorf("failed to build tag reference: %w", err)
	}

	// Verify current version digest if provided
	if img.digest != "" {
		check.log.Debug().
			Str("expected_digest", img.digest).
			Msg("verifying current version digest")

		actualDigest, err := checker.GetTagDigest(tagReference)
		if err != nil {
			return fmt.Errorf("failed to get current version digest: %w", err)
		}

		if actualDigest != img.digest {
			check.log.Error().
				Str("expected", img.digest).
				Str("actual", actualDigest).
				Str("version", img.version).
				Msg("current version digest mismatch")

			return fmt.Errorf(
				"%w: current version %s points to %s, expected %s",
				ErrDigestMismatch,
				tagReference,
				actualDigest,
				img.digest,
			)
		}

		check.log.Info().
			Str("digest", actualDigest).
			Msg("current version digest verification passed")
	} else {
		// Warn if no digest provided - show actual digest
		actualDigest, err := checker.GetTagDigest(tagReference)
		if err != nil {
			check.log.Warn().
				Err(err).
				Str("version", img.version).
				Msg("failed to retrieve current version digest for verification")
		} else {
			check.log.Warn().
				Str("tag", tagReference).
				Str("digest", actualDigest).
				Msgf("⚠ WARNING: No digest verification for %s. Add .Digest(\"%s\") to your Image to enable verification", tagReference, actualDigest)
		}
	}

	// Check for updates - variant auto-extracted from version
	info, err := checker.CheckVersion(img.name, img.version, "")
	if err != nil {
		return fmt.Errorf("failed to check version: %w", err)
	}

	// Store results for later retrieval
	check.currentVersion = info.CurrentVersion
	check.latestVersion = info.LatestVersion
	check.latestDigest = info.LatestDigest
	check.updateAvailable = info.UpdateAvailable
	check.executed = true

	if info.UpdateAvailable {
		check.log.Warn().
			Str("image", img.name).
			Str("current", info.CurrentVersion).
			Str("latest", info.LatestVersion).
			Str("digest", info.LatestDigest).
			Msg("⚠ UPDATE AVAILABLE")
	} else {
		check.log.Info().
			Str("tag", tagReference).
			Msg("✓ Up to date")
	}

	return nil
}

// CurrentVersion returns the current version that was checked.
// Only valid after plan execution.
func (check *VersionCheck) CurrentVersion() string {
	return check.currentVersion
}

// LatestVersion returns the latest available version.
// Only valid after plan execution.
func (check *VersionCheck) LatestVersion() string {
	return check.latestVersion
}

// LatestDigest returns the digest of the latest version.
// Only valid after plan execution.
func (check *VersionCheck) LatestDigest() string {
	return check.latestDigest
}

// UpdateAvailable returns whether an update is available.
// Only valid after plan execution.
func (check *VersionCheck) UpdateAvailable() bool {
	return check.updateAvailable
}

// Executed returns whether the version check has been executed.
func (check *VersionCheck) Executed() bool {
	return check.executed
}

// operationName returns the version check operation name (implements operation interface).
func (check *VersionCheck) operationName() string {
	return check.opName
}
