package sdk

import (
	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
)

// Registry represents a container registry with authentication.
type Registry struct {
	host     string
	username string
	password string
	log      zerolog.Logger
}

// RegistryBuilder builds a Registry.
type RegistryBuilder struct {
	plan     *Plan
	registry *Registry
}

// Username sets the registry username.
func (builder *RegistryBuilder) Username(username string) *RegistryBuilder {
	builder.registry.username = username

	return builder
}

// Password sets the registry password.
func (builder *RegistryBuilder) Password(password string) *RegistryBuilder {
	builder.registry.password = password

	return builder
}

// Build validates and stores the registry in the plan's registry collection.
// Returns the Registry for direct use (e.g., version checking before plan execution).
func (builder *RegistryBuilder) Build() *Registry {
	// Normalize the domain (empty string → docker.io)
	normalizedDomain := normalizeDomain(builder.registry.host)

	// Store in plan's registry map keyed by normalized domain
	builder.plan.registries[normalizedDomain] = builder.registry

	return builder.registry
}

// Host returns the registry host.
func (reg *Registry) Host() string {
	return reg.host
}

// Username returns the registry username.
func (reg *Registry) Username() string {
	return reg.username
}

// Password returns the registry password.
func (reg *Registry) Password() string {
	return reg.password
}

// GetDigest returns the digest for an image reference.
func (reg *Registry) GetDigest(imageRef string) (string, error) {
	client := registry.NewClient(reg.host, reg.username, reg.password, reg.log)
	//nolint:wrapcheck
	return client.GetDigest(imageRef)
}

// ListTags returns all tags for a repository.
func (reg *Registry) ListTags(repository string) ([]string, error) {
	client := registry.NewClient(reg.host, reg.username, reg.password, reg.log)
	//nolint:wrapcheck
	return client.ListTags(repository)
}
