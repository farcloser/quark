package version

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/reference"
)

//nolint:gochecknoglobals
var (
	// versionRegex extracts prefix, version, suffix from a tag.
	// Group 1: optional prefix (non-version chars ending with . or -)
	// Group 2: version (digits, dots, hyphens)
	// Group 3: optional suffix (everything else).
	versionRegex = regexp.MustCompile(`^([^0-9.-]*[.-])?v?([0-9.-]+)(.*)$`)

	// excludePatterns filters out development/test versions.
	excludePatterns = []string{
		"nightly", "dev", "beta", "alpha", "rc", "test", "snapshot", "builder",
	}
)

// versionParts holds the parsed components of a version tag.
type versionParts struct {
	Prefix  string
	Version string
	Suffix  string
}

// Checker checks for image version updates from OCI registries.
type Checker struct {
	client *registry.Client
	log    *slog.Logger
}

// NewChecker creates a new version checker using the provided registry client.
func NewChecker(client *registry.Client, log *slog.Logger) *Checker {
	return &Checker{
		client: client,
		log:    log,
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
// imageRef: parsed image reference (must include a tag).
// Filter is auto-detected from current tag: suffix if present, otherwise prefix.
func (checker *Checker) CheckVersion(ctx context.Context, imageRef reference.ImageReference) (*Info, error) {
	currentTag := imageRef.Tag

	// Require a tag for version checking
	if currentTag == "" {
		return nil, fmt.Errorf("%w: %s", fault.ErrInvalidArgument, imageRef.String())
	}

	currentParts := parseVersion(currentTag)

	// Auto-detect filter: use suffix if present, otherwise use prefix
	filter := currentParts.Suffix
	if filter == "" {
		filter = currentParts.Prefix
	}

	checker.log.DebugContext(ctx, "checking registry for updates", //revive:disable-line:add-constant
		"image", imageRef.String(),
		"current", currentTag,
		"filter", filter)

	// List all tags from registry using the registry client
	tags, err := checker.client.ListTags(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnableToListTags, err)
	}

	// Filter and collect valid versions
	var versions []string

	for _, tag := range tags {
		if isValidVersion(tag, filter) {
			versions = append(versions, tag)
		}
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoValidVersionsFound, imageRef.String())
	}

	// Sort versions semantically
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})

	// Only fetch digest for the latest version
	latestVersion := versions[len(versions)-1]

	// Construct the latest tag reference string and parse to ImageReference
	latestTagStr := fmt.Sprintf("%s:%s", imageRef.Name(), latestVersion)

	latestImageRef, err := reference.Parse(latestTagStr)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse latest tag: %w", fault.ErrInvalidArgument, err)
	}

	latestDigest, err := checker.client.GetDigest(ctx, *latestImageRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnableToGetDigest, err)
	}

	return &Info{
		CurrentVersion:  currentTag,
		LatestVersion:   latestVersion,
		LatestDigest:    latestDigest,
		UpdateAvailable: currentTag != latestVersion,
	}, nil
}

// parseVersion extracts prefix, version, and suffix from a tag.
// Version component has hyphens replaced with dots for normalization.
func parseVersion(tag string) versionParts {
	matches := versionRegex.FindStringSubmatch(tag)
	if matches == nil {
		return versionParts{Version: tag}
	}

	clean := ".-"

	version := strings.Trim(matches[2], clean)
	version = strings.ReplaceAll(version, "-", ".")

	return versionParts{
		Prefix:  strings.Trim(matches[1], clean),
		Version: version,
		Suffix:  strings.Trim(matches[3], clean),
	}
}

// isValidVersion checks if a tag matches the filter and isn't excluded.
func isValidVersion(tag, filter string) bool {
	lowerTag := strings.ToLower(tag)

	// Exclude development/test versions
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerTag, pattern) {
			return false
		}
	}

	// Parse the tag
	parts := parseVersion(tag)

	// Must have a version component
	if parts.Version == "" {
		return false
	}

	// If no filter, match tags with no prefix and no suffix
	if filter == "" {
		return parts.Prefix == "" && parts.Suffix == ""
	}

	// Match by suffix or prefix
	return parts.Suffix == filter || parts.Prefix == filter
}

// compareVersions compares two version strings semantically.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func compareVersions(tag1, tag2 string) int {
	parts1 := parseVersion(tag1)
	parts2 := parseVersion(tag2)

	// Split on dots (version is already normalized by parseVersion)
	segments1 := strings.Split(parts1.Version, ".")
	segments2 := strings.Split(parts2.Version, ".")

	// Compare each segment
	maxLen := max(len(segments2), len(segments1))

	for idx := range maxLen {
		var num1, num2 int

		if idx < len(segments1) {
			_, _ = fmt.Sscanf(segments1[idx], "%d", &num1)
		}

		if idx < len(segments2) {
			_, _ = fmt.Sscanf(segments2[idx], "%d", &num2)
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
