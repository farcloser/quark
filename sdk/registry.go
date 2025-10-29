package sdk

import (
	"fmt"
	"net"
	"strings"

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

const maxHostnameLength = 253 // RFC 1035 maximum hostname length

// isValidRegistryDomain validates a registry domain using lightweight checks.
// Accepts hostnames, IP addresses, and optional port numbers.
func isValidRegistryDomain(domain string) bool {
	// Empty domain is valid (normalizes to docker.io)
	if domain == "" {
		return true
	}

	// Split host and port if present
	host, _, err := net.SplitHostPort(domain)
	if err != nil {
		// No port present, use domain as host
		host = domain
	}

	// Check if it's a valid IP address
	if net.ParseIP(host) != nil {
		return true
	}

	// Check if it's a valid hostname (basic format check)
	// Must not be empty, must not start/end with hyphen or dot
	if len(host) == 0 || len(host) > maxHostnameLength {
		return false
	}

	if strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return false
	}

	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}

	// Must contain only valid hostname characters
	for _, char := range host {
		isLower := char >= 'a' && char <= 'z'
		isUpper := char >= 'A' && char <= 'Z'
		isDigit := char >= '0' && char <= '9'
		isSpecial := char == '.' || char == '-'
		isValid := isLower || isUpper || isDigit || isSpecial

		if !isValid {
			return false
		}
	}

	return true
}

// Build validates and stores the registry in the plan's registry collection.
// Returns the Registry for direct use (e.g., version checking before plan execution).
func (builder *RegistryBuilder) Build() (*Registry, error) {
	// Validate domain format
	if !isValidRegistryDomain(builder.registry.host) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRegistryDomain, builder.registry.host)
	}

	// Normalize the domain (empty string → docker.io)
	normalizedDomain := normalizeDomain(builder.registry.host)

	// Store in plan's registry map keyed by normalized domain
	builder.plan.registries[normalizedDomain] = builder.registry

	return builder.registry, nil
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
