package sdk_test

import (
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Credentials are optional.
func TestNewRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		domain string
	}{
		{
			name:   "domain without port",
			domain: "ghcr.io",
		},
		{
			name:   "domain with port",
			domain: "registry.example.com:5000",
		},
		{
			name:   "IP address without port",
			domain: "192.168.1.100",
		},
		{
			name:   "IP address with port",
			domain: "10.0.0.1:5000",
		},
		{
			name:   "localhost without port",
			domain: "localhost",
		},
		{
			name:   "localhost with port",
			domain: "localhost:5000",
		},
		{
			name:   "empty domain (normalizes to docker.io)",
			domain: "",
		},
		{
			name:   "docker.io explicit",
			domain: "docker.io",
		},
		{
			name:   "subdomain",
			domain: "registry.k8s.io",
		},
		{
			name:   "domain with hyphens",
			domain: "my-registry.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := sdk.NewRegistry(&sdk.RegistryOpts{Domain: tt.domain})

			if reg == nil {
				t.Error("NewRegistry() returned nil registry")
			}
		})
	}
}
