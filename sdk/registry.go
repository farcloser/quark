package sdk

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/types"
)

// Registry represents a container registry with credentials.
type Registry struct {
	resource.Resource

	options RegistryOpts
	log     *slog.Logger
}

// RegistryOpts configures registry creation.
type RegistryOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker  string
	Domain   string // registry domain (e.g., "ghcr.io", "docker.io")
	Username string // registry username
	Token    string // registry token or password
}

// NewRegistry creates a new Registry resource.
func NewRegistry(opts RegistryOpts) *Registry {
	if opts.Domain == "" {
		opts.Domain = defaultRegistry
	}

	moniker := opts.Moniker
	if moniker == "" {
		moniker = opts.Domain
	}

	output := &Registry{
		options: opts,
		log:     slog.With(registryResourceName, moniker),
	}

	moniker = fmt.Sprintf("%s:%s", registryResourceName, moniker)

	output.Resource = (&createRegistryAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker)),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}

// NewImage creates a new Image resource associated with this registry.
func (reg *Registry) NewImage(opts ImageOpts) *Image {
	moniker := opts.Moniker
	if moniker == "" {
		moniker = fmt.Sprintf("%s:%s:%s:%s", imageResourceName, opts.Name, opts.Version, opts.Digest)
	}

	output := &Image{
		options:  opts,
		registry: reg,
		log:      reg.log.With(imageResourceName, moniker),
	}

	moniker = fmt.Sprintf("%s:%s", imageResourceName, moniker)

	output.Resource = (&createImageAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker), reg),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}

// credentials returns the registry credentials.
func (reg *Registry) credentials() *types.RegistryCredentials {
	return &types.RegistryCredentials{
		Domain:   reg.options.Domain,
		Username: reg.options.Username,
		Password: reg.options.Token,
	}
}
