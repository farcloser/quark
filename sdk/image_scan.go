package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/dev/store"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/a_deprecated/sigstore"
	"github.com/farcloser/quark/internal/trivy"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/scan"
)

// vexPredicateTypePrefix is the prefix for OpenVEX predicate types.
const vexPredicateTypePrefix = "https://openvex.dev"

// vexFile represents a VEX file on disk with its associated lock.
// The caller must call Release() when done using the file.
type vexFile struct {
	Path    string
	release func()
}

// Release releases the read lock and attempts to clean up the VEX file.
func (vf *vexFile) Release() {
	if vf.release != nil {
		vf.release()
		vf.release = nil
	}
}

type scanAction struct {
	*resource.BaseAction

	opts   *scan.Options
	output *Image
}

func (sa *scanAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(sa, sa.BaseAction, name, out, copyFrom...)
}

func (sa *scanAction) Execute(ctx context.Context) error {
	output := sa.output

	// Scan can only scan by digest. Fail first if digest is NOT set
	if output.ref.Digest == "" {
		return fmt.Errorf("%w: %s", scan.ErrArgumentRequiredImageDigest, output.ref.String())
	}

	// Create Trivy scanner
	scanner, err := trivy.NewScanner(ctx, output.log)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	// Retrieve VEX attestations before scanning
	vexFiles := sa.retrieveVEXAttestations(ctx)

	defer func() {
		for _, vf := range vexFiles {
			vf.Release()
		}
	}()

	// Build scan options
	scanOpts := &trivy.ScanOptions{}
	if sa.opts != nil && sa.opts.ShowSuppressed {
		scanOpts.ShowSuppressed = true
	}

	// Add VEX file paths to scan options
	for _, vf := range vexFiles {
		scanOpts.VEXPaths = append(scanOpts.VEXPaths, vf.Path)
	}

	// Scan both platforms
	platforms := []*platform.Platform{platform.AMD64, platform.ARM64}

	trivyResult, err := scanner.ScanImage(
		ctx,
		output.ref.String(),
		[]string{platform.AMD64.String(), platform.ARM64.String()},
		scanOpts,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", scan.ErrScanFailed, err)
	}

	// Transform and deduplicate trivy results
	sa.output.scanResult = transformTrivyResults(trivyResult, platforms)

	return nil
}

// retrieveVEXAttestations fetches VEX attestations from the image and stores them
// in content-addressable storage. Returns vexFiles that must be released by caller.
func (sa *scanAction) retrieveVEXAttestations(ctx context.Context) []*vexFile {
	output := sa.output

	// Create registry client
	regClient := registry.NewClient(output.registry.credentials(), output.log)

	// Inspect attestations
	result, err := sigstore.InspectAttestations(ctx, &sigstore.InspectAttestationsOptions{
		ImageRef:       *output.ref,
		Digest:         output.ref.Digest.String(),
		RegistryClient: regClient,
		Log:            output.log,
	})
	if err != nil {
		output.log.DebugContext(ctx, "failed to inspect attestations for VEX",
			slog.String("image", output.ref.String()),
			slog.String("reason", err.Error()))

		return nil
	}

	if !result.HasAttestations {
		output.log.DebugContext(ctx, "no attestations found for VEX lookup",
			slog.String("image", output.ref.String()))

		return nil
	}

	// Filter for VEX attestations and store them
	var vexFiles []*vexFile

	for idx, att := range result.Attestations {
		if !strings.HasPrefix(att.PredicateType, vexPredicateTypePrefix) {
			continue
		}

		output.log.InfoContext(ctx, "found VEX attestation",
			slog.String("image", output.ref.String()),
			slog.Int("index", idx),
			slog.String("predicateType", att.PredicateType))

		// Store VEX predicate in content-addressable storage
		path, release, err := store.GetStoreVolatile().Acquire(att.Predicate)
		if err != nil {
			output.log.DebugContext(ctx, "failed to store VEX attestation",
				slog.Int("index", idx),
				slog.String("reason", err.Error()))

			continue
		}

		vexFiles = append(vexFiles, &vexFile{
			Path:    path,
			release: release,
		})
	}

	if len(vexFiles) > 0 {
		output.log.InfoContext(ctx, "VEX attestations retrieved",
			slog.String("image", output.ref.String()),
			slog.Int("count", len(vexFiles)))
	}

	return vexFiles
}

// transformTrivyResults converts raw trivy results into deduplicated scan.Result.
// Vulnerabilities are deduplicated by CVE+PURL, with targets tracking component and platform.
func transformTrivyResults(trivyResult *trivy.ScanResult, platforms []*platform.Platform) *scan.Result {
	// Key for deduplication: CVE ID + PURL
	type vulnKey struct {
		id   string
		purl string
	}

	seen := make(map[vulnKey]*scan.Vulnerability)

	var order []vulnKey // Preserve insertion order

	// Trivy returns results grouped by target (component), alternating between platforms
	// e.g., [amd64-target1, amd64-target2, arm64-target1, arm64-target2]
	// We need to figure out which platform each result belongs to
	resultsPerPlatform := len(trivyResult.Results) / len(platforms)

	for idx, trivyRes := range trivyResult.Results {
		// Determine platform based on result index
		platformIdx := idx / resultsPerPlatform
		if platformIdx >= len(platforms) {
			platformIdx = len(platforms) - 1
		}

		plat := platforms[platformIdx]
		target := trivyRes.Target

		for _, vuln := range trivyRes.Vulnerabilities {
			// Normalize PURL by removing arch parameter for deduplication
			// (arch is already captured in Targets via platform)
			normalizedPURL := normalizePURL(vuln.PkgIdentifier.PURL)
			key := vulnKey{id: vuln.VulnerabilityID, purl: normalizedPURL}

			if existing, exists := seen[key]; exists {
				// Add platform to existing target, or create new target entry
				if existing.Targets[target] == nil {
					existing.Targets[target] = []*platform.Platform{plat}
				} else if !containsPlatform(existing.Targets[target], plat) {
					existing.Targets[target] = append(existing.Targets[target], plat)
				}
			} else {
				// New vulnerability
				newVuln := &scan.Vulnerability{
					ID:               vuln.VulnerabilityID,
					PkgName:          vuln.PkgName,
					InstalledVersion: vuln.InstalledVersion,
					FixedVersion:     vuln.FixedVersion,
					Severity:         scan.ParseSeverity(vuln.Severity),
					Title:            vuln.Title,
					PURL:             normalizedPURL,
					Targets: map[string][]*platform.Platform{
						target: {plat},
					},
				}
				seen[key] = newVuln
				order = append(order, key)
			}
		}
	}

	// Build result slice in insertion order
	vulns := make([]scan.Vulnerability, 0, len(order))
	for _, key := range order {
		vulns = append(vulns, *seen[key])
	}

	return &scan.Result{Vulnerabilities: vulns}
}

func containsPlatform(platforms []*platform.Platform, p *platform.Platform) bool {
	return slices.Contains(platforms, p)
}

// normalizePURL removes the arch query parameter from a PURL.
// This allows deduplication across architectures since arch is tracked separately in Targets.
// e.g., "pkg:deb/debian/foo@1.0?arch=amd64&distro=debian-13" -> "pkg:deb/debian/foo@1.0?distro=debian-13".
func normalizePURL(purl string) string {
	// Find the query string portion
	queryStart := strings.Index(purl, "?")
	if queryStart == -1 {
		return purl // No query params
	}

	basePURL := purl[:queryStart]
	queryString := purl[queryStart+1:]

	// Parse and filter query params
	params, err := url.ParseQuery(queryString)
	if err != nil {
		return purl // Return original if parsing fails
	}

	// Remove arch parameter
	params.Del("arch")

	if len(params) == 0 {
		return basePURL
	}

	return basePURL + "?" + params.Encode()
}
