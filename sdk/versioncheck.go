package sdk

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/version"
)

// VersionCheckResult contains the result of a version check operation.
type VersionCheckResult struct {
	// CurrentVersion is the version that was checked.
	CurrentVersion string
	// LatestVersion is the latest available version.
	LatestVersion string
	// LatestDigest is the digest of the latest version.
	LatestDigest string
	// UpdateAvailable indicates whether an update is available.
	UpdateAvailable bool
}

// versionCheckOp represents a version check operation.
type versionCheckOp struct {
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
}

func (v *versionCheckOp) execute(_ context.Context) error {
	img := v.image

	v.log.Info().
		Str("image", img.Name()).
		Str("version", img.Version()).
		Msg("checking for version updates")

	// Create version checker with optional registry credentials
	var username, password string
	if v.registry != nil {
		username = v.registry.username
		password = v.registry.token
	}

	checker := version.NewChecker(username, password, v.log)

	// Check for version updates first
	info, err := checker.CheckVersion(img.Name(), img.Version(), "")
	if err == nil && info.UpdateAvailable {
		// Newer version available - use it
		v.currentVersion = info.CurrentVersion
		v.latestVersion = info.LatestVersion
		v.latestDigest = info.LatestDigest
		v.updateAvailable = true

		v.log.Warn().
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
	if digestMismatch && !v.force {
		v.log.Error().
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
	v.currentVersion = img.Version()
	v.latestVersion = img.Version()
	v.latestDigest = actualDigest
	v.updateAvailable = (v.force && (digestMismatch || expectedDigest == ""))

	if v.updateAvailable {
		v.log.Warn().
			Str("version", v.currentVersion).
			Str("digest", v.latestDigest).
			Msg("⚠ digest update (force mode)")
	} else {
		v.log.Info().
			Str("version", v.currentVersion).
			Str("digest", v.latestDigest).
			Msg("✓ up to date")
	}

	return nil
}

// operationName returns the version check operation name (implements operation interface).
func (v *versionCheckOp) operationName() string {
	return v.opName
}
