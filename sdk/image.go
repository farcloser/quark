package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/dockle"
	sigstore2 "github.com/farcloser/quark/internal/a_deprecated/sigstore"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/sdk/attest"
	"github.com/farcloser/quark/sdk/audit"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/policy"
	"github.com/farcloser/quark/sdk/scan"
	"github.com/farcloser/quark/sdk/sign"
	"github.com/farcloser/quark/sdk/sync"
	"github.com/farcloser/quark/sdk/update"
)

// Image represents a container image reference.
type Image struct {
	resource.Resource

	options  ImageOpts
	ref      *reference.ImageReference
	log      *slog.Logger
	registry *Registry

	// Results from previous actions (populated during execution)
	scanResult       *scan.Result
	auditResult      *dockle.ScanResult
	signatureInfo    *sigstore2.InspectResult
	attestationsInfo *sigstore2.AttestationsResult
}

// ImageOpts contains configuration options for creating an image reference.
type ImageOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker string
	Name    string `json:"name"`              // Required - image name (e.g., "alpine", "org/image", "ghcr.io/foo/bar")
	Version string `json:"version,omitempty"` // Optional - image tag/version
	Digest  string `json:"digest,omitempty"`  // Optional - image digest for verification
}

func (img *Image) Moniker() string {
	moniker := img.options.Moniker
	if moniker == "" {
		moniker = fmt.Sprintf(
			"%s:%s:%s",
			img.options.Name,
			img.options.Version,
			img.options.Digest,
		)
	}

	return fmt.Sprintf("%s:%s", imageResourceName, moniker)
}

// Copy copies this image's runtime state to another image.
func (img *Image) Copy(dest resource.Resource) error {
	destImg, ok := dest.(*Image)
	if !ok {
		img.log.Error("Copy: destination is not an Image, skipping", "dest", fmt.Sprintf("%T", dest))

		return nil
	}

	// Copy runtime state (ref is the parsed/enriched state)
	// Deep copy the reference to avoid shared mutation
	refCopy := *img.ref
	destImg.ref = &refCopy

	// Copy action results for policy evaluation
	destImg.scanResult = img.scanResult
	destImg.auditResult = img.auditResult
	destImg.signatureInfo = img.signatureInfo
	destImg.attestationsInfo = img.attestationsInfo

	// Note: options, log, registry are set at construction time and don't need copying
	// They should already be the same or appropriately set on dest

	return nil
}

// Digest returns the image digest, if available.
// The digest may be set from the original options, or populated after actions like Sync, Verify, or Build.
// Must be called after plan execution.
func (img *Image) Digest() string {
	return img.ref.Digest.String()
}

// Domain returns the registry domain for this image.
// Must be called after plan execution.
func (img *Image) Domain() string {
	return img.registry.options.Domain
}

// Name returns the image name (path without domain, e.g., "library/alpine").
// Must be called after plan execution.
func (img *Image) Name() string {
	return img.ref.Path
}

// Version returns the image tag/version.
// Must be called after plan execution.
func (img *Image) Version() string {
	return img.ref.Tag
}

// Attestations returns attestation information for the image.
// Returns nil if no attestations have been retrieved (call Sync() first).
// Must be called after plan execution.
func (img *Image) Attestations() *sigstore2.AttestationsResult {
	return img.attestationsInfo
}

// Scan schedules a vulnerability scan on the image.
// Returns a new Image representing the post-scan state.
func (img *Image) Scan(opts *scan.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&scanAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionScanName, output.Moniker()), img),
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Audit schedules an audit on the image.
// Returns a new Image representing the post-audit state.
func (img *Image) Audit(opts *audit.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&auditAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionAuditName, output.Moniker()), img),
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Sync resolves the image digest (if not set) and retrieves signature information.
// This action does not enforce any policy - use Check() with signature policies for that.
// Returns a new Image representing the post-sync state with digest and signature info populated.
func (img *Image) Sync() *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&syncMetadataAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionSyncName, output.Moniker()), img),
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Sign schedules signing of the image.
// Returns a new Image representing the post-sign state.
func (img *Image) Sign(signer *Signer, opts *sign.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&signAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionSignName, output.Moniker()), img, signer),
		signer:     signer,
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Attest schedules attaching VEX attestations to the image.
// VEX attestations are used by vulnerability scanners (e.g., Trivy with --vex oci)
// to filter vulnerabilities that don't apply to this specific image.
// Returns a new Image representing the post-attest state.
func (img *Image) Attest(signer *Signer, opts *attest.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&attestAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionAttestName, output.Moniker()), img, signer),
		signer:     signer,
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// CopyTo schedules copying this image to a destination image.
// Returns the destination Image representing the post-copy state.
func (img *Image) CopyTo(dest *Image, opts *sync.Options) *Image {
	if opts == nil {
		opts = &sync.Options{}
	}

	if opts.Platforms == nil {
		opts.Platforms = []*platform.Platform{platform.ARM64, platform.AMD64}
	}

	// Output is based on dest (destination registry/name), not source
	output := &Image{
		options:  dest.options,
		log:      dest.log,
		registry: dest.registry,
	}

	output.Resource = (&copyAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s->%s", actionCopyName, img.Moniker(), output.Moniker()), img, dest),
		source:     img,
		dest:       dest,
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, dest)

	return output
}

// Update schedules checking for and applying version updates to the image.
// If the image has no tag, warns and returns without error.
// If a newer version is found, updates the image tag and nullifies the digest.
// Returns a new Image representing the post-update state.
func (img *Image) Update(opts *update.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&updateAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionUpdateName, output.Moniker()), img),
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Do schedules a custom action on the image.
// The function receives the output image (with state copied from input via Bootstrap).
// Returns a new Image representing the post-action state.
//
// Example:
//
//	out := img.Do("enrich-digest", func(ctx context.Context, output *Image) error {
//	    // output.ref has been populated from img
//	    output.ref.Digest = resolvedDigest
//	    return nil
//	})
func (img *Image) Do(
	name string,
	doFunc func(ctx context.Context, output *Image) error,
) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&doAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s:%s", actionDoName, name, output.Moniker()), img),
		fn:         doFunc,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Check schedules a policy check on the image.
// The policy is evaluated against the image's current state, including
// results from previous actions (Scan, Audit, Verify).
// Returns a new Image representing the post-check state.
func (img *Image) Check(pol policy.Policy) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&checkAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s:%s", actionCheckName, pol.Name(), output.Moniker()), img),
		policy:     pol,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// Log schedules logging of scan/audit results attached to the image.
// Results are formatted and output to the logger based on the configured
// severity-to-log-level mapping.
// Returns a new Image representing the post-log state.
func (img *Image) Log(opts *sdklog.Options) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&logAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionLogName, output.Moniker()), img),
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, img)

	return output
}

// With creates a new Image that depends on the current image and additional resources.
// Use this to express ordering constraints when there's no direct data dependency.
// Returns a new Image for chaining.
func (img *Image) With(deps ...resource.Resource) *Image {
	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = resource.NewWithAction("with:"+img.options.Name, img, deps...).
		AddOutput(img.options.Name, output, img)

	return output
}
