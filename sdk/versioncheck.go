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
	force    bool // if true, digest mismatches are warnings instead of errors

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
	built bool
}

// Source sets the source image.
// The image must have a version specified. Digest is optional:
// - If digest is provided: verifies the version tag points to expected digest (fails on mismatch)
// - If digest is not provided: shows warning with actual digest
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found, anonymous access will be used (public repos only).
func (builder *VersionCheckBuilder) Source(image *Image) *VersionCheckBuilder {
	builder.check.image = image
	builder.check.registry = builder.plan.getRegistry(image.Domain())

	return builder
}

// Force enables force mode for digest verification.
// When enabled, digest mismatches become warnings instead of errors,
// and the digest is updated with the actual value from the remote.
func (builder *VersionCheckBuilder) Force(force bool) *VersionCheckBuilder {
	builder.check.force = force

	return builder
}

// Build validates and adds the version check to the plan.
// The builder becomes unusable after Build() is called.
// Create a new builder for each operation.
func (builder *VersionCheckBuilder) Build() (*VersionCheck, error) {
	if builder.built {
		return nil, ErrBuilderAlreadyUsed
	}

	builder.built = true

	if builder.check.image == nil {
		return nil, ErrVersionCheckImageRequired
	}

	if builder.check.image.Version() == "" {
		return nil, ErrVersionCheckVersionRequired
	}

	builder.plan.versionChecks = append(builder.plan.versionChecks, builder.check)
	builder.plan.operations = append(builder.plan.operations, builder.check)

	return builder.check, nil
}

func (check *VersionCheck) execute(_ context.Context) error {
	img := check.image

	// Version check requires explicit version (not defaulted "latest")
	imgVersion := img.Version()
	if imgVersion == "" {
		return fmt.Errorf("%w for image %q", ErrVersionCheckExplicitVersionRequired, img.Name())
	}

	// Don't check for updates on "latest" tag
	if imgVersion == "latest" {
		return fmt.Errorf("%w on image %q", ErrVersionCheckLatestNotSupported, img.Name())
	}

	check.log.Info().
		Str("image", img.Name()).
		Str("version", img.Version()).
		Msg("checking for version updates")

	// Create version checker with optional registry credentials
	var username, password string
	if check.registry != nil {
		username = check.registry.username
		password = check.registry.password
	}

	checker := version.NewChecker(username, password, check.log)

	// Check for version updates first
	info, err := checker.CheckVersion(img.Name(), img.Version(), "")
	if err == nil && info.UpdateAvailable {
		// Newer version available - use it
		check.currentVersion = info.CurrentVersion
		check.latestVersion = info.LatestVersion
		check.latestDigest = info.LatestDigest
		check.updateAvailable = true
		check.executed = true

		check.log.Warn().
			Str("current", info.CurrentVersion).
			Str("latest", info.LatestVersion).
			Str("digest", info.LatestDigest).
			Msg("⚠ update available")

		return nil
	}

	// No newer version - check current version digest
	actualDigest, err := checker.GetDigest(img.tagRef())
	if err != nil {
		return fmt.Errorf("failed to get current version digest: %w", err)
	}

	expectedDigest := img.Digest()
	digestMismatch := (expectedDigest != "" && actualDigest != expectedDigest)

	// Fail on digest mismatch unless force mode
	if digestMismatch && !check.force {
		check.log.Error().
			Str("expected", expectedDigest).
			Str("actual", actualDigest).
			Str("version", img.Version()).
			Msg("digest mismatch")

		return fmt.Errorf(
			"%w: current version %s points to %s, expected %s",
			ErrDigestMismatch,
			img.Name(),
			actualDigest,
			expectedDigest,
		)
	}

	// No version update, set current as latest
	check.currentVersion = img.Version()
	check.latestVersion = img.Version()
	check.latestDigest = actualDigest
	check.updateAvailable = (check.force && (digestMismatch || expectedDigest == ""))
	check.executed = true

	if check.updateAvailable {
		check.log.Warn().
			Str("version", check.currentVersion).
			Str("digest", check.latestDigest).
			Msg("⚠ digest update (force mode)")
	} else {
		check.log.Info().
			Str("version", check.currentVersion).
			Str("digest", check.latestDigest).
			Msg("✓ up to date")
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
