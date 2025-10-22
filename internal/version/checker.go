// Package version provides OCI registry version checking.
package version

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rs/zerolog"
)

var errNoValidVersionsFound = errors.New("no valid versions found")

// Checker checks for image version updates from OCI registries.
type Checker struct {
	username string
	password string
	log      zerolog.Logger
}

// NewChecker creates a new version checker with optional authentication.
func NewChecker(username, password string, log zerolog.Logger) *Checker {
	return &Checker{
		username: username,
		password: password,
		log:      log,
	}
}

// Info contains version information for an image.
type Info struct {
	CurrentVersion  string
	LatestVersion   string
	LatestDigest    string
	UpdateAvailable bool
}

// CheckVersion checks any OCI registry for the latest version of an image.
// imageRef: full image reference (e.g., "timberio/vector", "docker.io/caddy", "ghcr.io/org/image")
// currentVersion: current version tag (e.g., "2.10.2-distroless-static" or "1.2.3")
// variant: optional variant suffix (e.g., "alpine", "distroless-static").
//
//	If empty, variant will be automatically extracted from currentVersion.
func (checker *Checker) CheckVersion(imageRef, currentVersion, variant string) (*Info, error) {
	// Auto-extract variant from currentVersion if not explicitly provided
	if variant == "" {
		_, extractedVariant := extractVariant(currentVersion)
		variant = extractedVariant
	}

	checker.log.Debug().
		Str("image", imageRef).
		Str("current", currentVersion).
		Str("variant", variant).
		Msg("checking registry for updates")

	// Parse repository reference
	repo, err := name.NewRepository(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}

	// List all tags from registry
	tags, err := remote.List(repo, checker.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	// Filter versions
	var versions []string

	for _, tag := range tags {
		if isValidVersion(tag, variant) {
			versions = append(versions, tag)
		}
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("%w: %s", errNoValidVersionsFound, imageRef)
	}

	// Sort versions semantically
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})

	// Only fetch digest for the latest version (not all versions)
	latestVersion := versions[len(versions)-1]

	latestTagRef, err := name.ParseReference(fmt.Sprintf("%s:%s", imageRef, latestVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest version reference: %w", err)
	}

	latestDesc, err := remote.Get(latestTagRef, checker.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest version digest: %w", err)
	}

	latestDigest := latestDesc.Digest.String()

	info := &Info{
		CurrentVersion:  currentVersion,
		LatestVersion:   latestVersion,
		LatestDigest:    latestDigest,
		UpdateAvailable: currentVersion != latestVersion,
	}

	if info.UpdateAvailable {
		checker.log.Info().
			Str("image", imageRef).
			Str("current", currentVersion).
			Str("latest", latestVersion).
			Msg("update available")
	} else {
		checker.log.Debug().
			Str("image", imageRef).
			Str("version", currentVersion).
			Msg("up to date")
	}

	return info, nil
}

// remoteOptions returns remote options with authentication if configured.
func (checker *Checker) remoteOptions() []remote.Option {
	if checker.username != "" && checker.password != "" {
		auth := &authn.Basic{
			Username: checker.username,
			Password: checker.password,
		}

		return []remote.Option{remote.WithAuth(auth)}
	}

	return []remote.Option{}
}

// isValidVersion checks if a tag is a valid semantic version.
// It filters out development tags like "nightly", "beta", "rc", etc.
// If variant is specified, only matches versions with that variant suffix.
func isValidVersion(tag, variant string) bool {
	// Exclude development/test versions
	excludePatterns := []string{
		"nightly", "dev", "beta", "alpha", "rc", "test", "snapshot", "builder",
	}
	lowerTag := strings.ToLower(tag)

	for _, pattern := range excludePatterns {
		if strings.Contains(lowerTag, pattern) {
			return false
		}
	}

	if variant != "" {
		// Match version with specific variant (e.g., "2.10.2-alpine")
		pattern := fmt.Sprintf(`^v?[0-9]+\.[0-9]+[0-9.]*-%s$`, regexp.QuoteMeta(variant))
		matched, _ := regexp.MatchString(pattern, tag)

		return matched
	}

	// Match plain version tags (e.g., "v2.9.13", "1.2.3")
	matched, _ := regexp.MatchString(`^v?[0-9]+\.[0-9]+[0-9.]*$`, tag)

	return matched
}

// compareVersions compares two semantic version strings.
// Returns -1 if version1 < version2, 0 if version1 == version2, 1 if version1 > version2.
func compareVersions(version1, version2 string) int {
	// Strip 'v' prefix and variant suffix
	version1 = stripVersionPrefix(version1)
	version2 = stripVersionPrefix(version2)

	// Split on dots
	parts1 := strings.Split(version1, ".")
	parts2 := strings.Split(version2, ".")

	// Compare each part
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for idx := range maxLen {
		var num1, num2 int

		if idx < len(parts1) {
			_, _ = fmt.Sscanf(parts1[idx], "%d", &num1)
		}

		if idx < len(parts2) {
			_, _ = fmt.Sscanf(parts2[idx], "%d", &num2)
		}

		if num1 < num2 {
			return -1
		}

		if num1 > num2 {
			return 1
		}
	}

	return 0
}

// stripVersionPrefix removes the 'v' prefix and extracts just the numeric version.
func stripVersionPrefix(version string) string {
	// Remove 'v' prefix
	version = strings.TrimPrefix(version, "v")

	// Extract version before variant suffix (e.g., "2.10.2" from "2.10.2-alpine")
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}

	return version
}

// extractVariant extracts the variant suffix from a version string.
// Examples:
//   - "0.50.0-distroless-static" → version="0.50.0", variant="distroless-static"
//   - "2.9.13-alpine" → version="2.9.13", variant="alpine"
//   - "1.2.3" → version="1.2.3", variant=""
//   - "v1.2.3-alpine" → version="1.2.3", variant="alpine"
func extractVariant(fullVersion string) (version, variant string) {
	// Strip 'v' prefix first
	fullVersion = strings.TrimPrefix(fullVersion, "v")

	// Find first hyphen after version numbers
	if version, variant, ok := strings.Cut(fullVersion, "-"); ok {
		return version, variant
	}

	// No variant found
	return fullVersion, ""
}

// GetTagDigest fetches the digest for a specific tag from any OCI registry.
func (checker *Checker) GetTagDigest(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference: %w", err)
	}

	desc, err := remote.Get(ref, checker.remoteOptions()...)
	if err != nil {
		return "", fmt.Errorf("failed to get image descriptor: %w", err)
	}

	return desc.Digest.String(), nil
}
