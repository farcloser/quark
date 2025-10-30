package sdk_test

import (
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Credentials are optional.
func TestRegistryBuilder_Build(t *testing.T) {
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

			plan := sdk.NewPlan("test-plan")

			reg, err := plan.Registry(tt.domain).Build()
			if err != nil {
				t.Errorf("Build() unexpected error = %v", err)

				return
			}

			if reg == nil {
				t.Error("Build() returned nil registry with nil error")
			}
		})
	}
}

// INTENTION: Credentials should be optional and properly stored.
func TestRegistryBuilder_Credentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		username     string
		password     string
		wantUsername string
		wantPassword string
	}{
		{
			name:         "with credentials",
			username:     "testuser",
			password:     "testpass",
			wantUsername: "testuser",
			wantPassword: "testpass",
		},
		{
			name:         "empty credentials",
			username:     "",
			password:     "",
			wantUsername: "",
			wantPassword: "",
		},
		{
			name:         "username only",
			username:     "testuser",
			password:     "",
			wantUsername: "testuser",
			wantPassword: "",
		},
		{
			name:         "password only",
			username:     "",
			password:     "testpass",
			wantUsername: "",
			wantPassword: "testpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")

			reg, err := plan.Registry("ghcr.io").
				Username(tt.username).
				Password(tt.password).
				Build()
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}

			if reg.Username() != tt.wantUsername {
				t.Errorf("Username() = %q, want %q", reg.Username(), tt.wantUsername)
			}

			if reg.Password() != tt.wantPassword {
				t.Errorf("Password() = %q, want %q", reg.Password(), tt.wantPassword)
			}
		})
	}
}

// INTENTION: The host value should be stored exactly as provided (before normalization).
func TestRegistryBuilder_HostPreservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		host     string
		wantHost string
	}{
		{
			name:     "ghcr.io",
			host:     "ghcr.io",
			wantHost: "ghcr.io",
		},
		{
			name:     "with port",
			host:     "registry.local:5000",
			wantHost: "registry.local:5000",
		},
		{
			name:     "IP address",
			host:     "192.168.1.100",
			wantHost: "192.168.1.100",
		},
		{
			name:     "IP with port",
			host:     "10.0.0.1:5000",
			wantHost: "10.0.0.1:5000",
		},
		{
			name:     "empty normalizes to docker.io",
			host:     "",
			wantHost: "docker.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")

			reg, err := plan.Registry(tt.host).Build()
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}

			// Note: Host() might return normalized value
			// This test verifies the behavior is consistent
			if reg.Host() != tt.wantHost {
				t.Errorf("Host() = %q, want %q", reg.Host(), tt.wantHost)
			}
		})
	}
}
