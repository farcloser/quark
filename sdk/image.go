package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/sdk/audit"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/scan"
	"github.com/farcloser/quark/sdk/sign"
	"github.com/farcloser/quark/sdk/sync"
	"github.com/farcloser/quark/sdk/update"
	"github.com/farcloser/quark/sdk/verify"
)

// Image represents a container image reference.
type Image struct {
	resource.BaseResource[Image]
	opts     ImageOpts
	ref      *reference.ImageReference
	log      *slog.Logger
	registry *Registry
}

// ImageOpts contains configuration options for creating an image reference.
type ImageOpts struct {
	Name    string `json:"name"`              // Required - image name (e.g., "alpine", "org/image", "ghcr.io/foo/bar")
	Version string `json:"version,omitempty"` // Optional - image tag/version
	Digest  string `json:"digest,omitempty"`  // Optional - image digest for verification
}

// Execute initializes the image reference by parsing the opts.
// This is called automatically during plan execution.
func (img *Image) Execute(_ context.Context) error {
	name := strings.TrimSpace(img.opts.Name)
	if name == "" {
		return ErrImageNameRequired
	}

	refString := ""
	if img.registry.opts.Domain != "" {
		refString = img.registry.opts.Domain + "/"
	}

	refString += name

	if img.opts.Version != "" {
		refString += ":" + img.opts.Version
	}

	if img.opts.Digest != "" {
		refString += "@" + img.opts.Digest
	}

	var err error

	img.ref, err = reference.Parse(refString)
	if err != nil {
		return ErrInvalidImageReference
	}

	return nil
}

// Digest returns the image digest, if available.
// The digest may be set from the original opts, or populated after actions like Sync, Verify, or Build.
// Must be called after plan execution.
func (img *Image) Digest() string {
	return img.ref.Digest.String()
}

// Domain returns the registry domain for this image.
// Must be called after plan execution.
func (img *Image) Domain() string {
	return img.registry.opts.Domain
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

// clone creates a copy of the image with a fresh BaseResource.
// Used by action methods to return a new image representing post-action state.
func (img *Image) clone() *Image {
	result := &Image{
		opts:     img.opts,
		ref:      img.ref,
		log:      img.log,
		registry: img.registry,
	}
	result.BaseResource = resource.NewBaseResource(result, img.ResourceName())

	return result
}

// Scan schedules a vulnerability scan on the image.
// Returns a new Image representing the post-scan state for chaining.
func (img *Image) Scan(sa *scan.Options) *Image {
	action := &scanAction{
		image: img,
		opts:  sa,
		log:   img.log.With("component", "scanner"),
	}
	action.BaseResource = resource.NewBaseResource(action, "scan:"+img.ResourceName())
	action.DependsOn(img)

	result := img.clone()
	result.DependsOn(action)

	return result
}

// Audit schedules an audit on the image.
// Returns a new Image representing the post-audit state for chaining.
func (img *Image) Audit(sa *audit.Options) *Image {
	action := &auditAction{
		image: img,
		opts:  sa,
		log:   img.log.With("component", "auditor"),
	}
	action.BaseResource = resource.NewBaseResource(action, "audit:"+img.ResourceName())
	action.DependsOn(img)

	result := img.clone()
	result.DependsOn(action)

	return result
}

// Verify schedules verification of the image signature.
// Returns a new Image representing the post-verify state for chaining.
func (img *Image) Verify(vo *verify.Options) *Image {
	action := &verifyAction{
		image: img,
		opts:  vo,
		log:   img.log.With("component", "verifier"), //revive:disable-line:add-constant
	}
	action.BaseResource = resource.NewBaseResource(action, "verify:"+img.ResourceName())
	action.DependsOn(img)

	result := img.clone()
	result.DependsOn(action)

	return result
}

// Sign schedules signing of the image.
// Returns a new Image representing the post-sign state for chaining.
func (img *Image) Sign(signer *Signer, so *sign.Options) *Image {
	action := &signAction{
		image:  img,
		signer: signer,
		opts:   so,
		log:    img.log.With("component", "signer"),
	}
	action.BaseResource = resource.NewBaseResource(action, "sign:"+img.ResourceName())
	action.DependsOn(img)
	action.DependsOn(signer)

	result := img.clone()
	result.DependsOn(action)

	return result
}

// SyncTo schedules syncing this image to a destination image.
// Returns the destination Image representing the post-sync state for chaining.
func (img *Image) SyncTo(dest *Image, syncOptions *sync.Options) *Image {
	if syncOptions == nil {
		syncOptions = &sync.Options{}
	}

	if syncOptions.Platforms == nil {
		syncOptions.Platforms = []platform.Platform{platform.ARM64, platform.AMD64}
	}

	action := &syncAction{
		source: img,
		dest:   dest,
		opts:   syncOptions,
		log:    img.log.With("component", "sync-to"),
	}
	action.BaseResource = resource.NewBaseResource(
		action,
		fmt.Sprintf("sync:%s->%s", img.ResourceName(), dest.ResourceName()),
	)
	action.DependsOn(img)
	action.DependsOn(dest)

	result := dest.clone()
	result.DependsOn(action)

	return result
}

// Update schedules checking for and applying version updates to the image.
// If the image has no tag, warns and returns without error.
// If a newer version is found, updates the image tag and nullifies the digest.
// Returns a new Image representing the post-update state for chaining.
func (img *Image) Update(uo *update.Options) *Image {
	action := &updateAction{
		image: img,
		opts:  uo,
		log:   img.log.With("component", "updater"),
	}
	action.BaseResource = resource.NewBaseResource(action, "update:"+img.ResourceName())
	action.DependsOn(img)

	result := img.clone()
	result.DependsOn(action)

	return result
}
