package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/utilities"
)

const (
	registryResourceName = "registry"
	imageResourceName    = "image"
)

// Registry represents a container registry with credentials.
type Registry struct {
	resource.BaseResource[Registry]

	opts RegistryOpts
}

// RegistryOpts configures registry creation.
type RegistryOpts struct {
	Domain   string // Required - registry domain (e.g., "ghcr.io", "docker.io")
	Username string // Optional - registry username
	Token    string // Optional - registry token or password
}

// NewRegistry creates a new Registry resource.
// The registry is validated during plan execution via a ping check.
func NewRegistry(opts RegistryOpts) *Registry {
	name := registryResourceName
	if opts.Domain != "" {
		name = fmt.Sprintf("%s:%s", name, opts.Domain)
	}

	reg := &Registry{
		opts: opts,
	}

	reg.BaseResource = resource.NewBaseResource(reg, name)

	return reg
}

// Execute performs preflight authentication check against the registry.
func (reg *Registry) Execute(ctx context.Context) error {
	slog.DebugContext(ctx, "authenticating with registry", "domain", reg.opts.Domain)

	client := registry.NewClient(reg.credentials(), slog.With("", ""))

	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRegistryAuth, reg.ResourceName(), err)
	}

	slog.DebugContext(ctx, "registry authentication successful", "domain", reg.opts.Domain)

	return nil
}

// NewImage creates a new Image resource associated with this registry.
// The image automatically depends on the registry for authentication.
func (reg *Registry) NewImage(opts ImageOpts) *Image {
	name := imageResourceName
	name = fmt.Sprintf("%s:%s", name, opts.Name)

	if opts.Version != "" {
		name = fmt.Sprintf("%s:%s", name, opts.Version)
	}

	if opts.Digest != "" {
		name = fmt.Sprintf("%s@%s", name, opts.Digest)
	}

	img := &Image{
		opts:     opts,
		registry: reg,
		log:      slog.With("image", name),
	}

	img.BaseResource = resource.NewBaseResource(img, name)
	img.DependsOn(reg)

	return img
}

// credentials returns the registry credentials as a shared.RegistryCredentials.
func (reg *Registry) credentials() *utilities.RegistryCredentials {
	return &utilities.RegistryCredentials{
		Domain:   reg.opts.Domain,
		Username: reg.opts.Username,
		Token:    reg.opts.Token,
	}
}
