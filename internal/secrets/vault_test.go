package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/fault"
	"github.com/hashicorp/vault/api"

	"github.com/farcloser/quark/internal/secrets"
	testvault "github.com/farcloser/quark/testutil/vault"
)

// seedTestSecrets creates standard test secrets in Vault for testing.
func seedTestSecrets(ctx context.Context, t *testing.T, address, token string) {
	t.Helper()

	config := api.DefaultConfig()
	config.Address = address

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}

	client.SetToken(token)

	kvClient := client.KVv2("secret")

	// Simple key-value secret
	_, err = kvClient.Put(ctx, "myapp/db", map[string]any{
		"username": "admin",
		"password": "secret123",
		"host":     "db.example.com",
		"port":     5432,
	})
	if err != nil {
		t.Fatalf("failed to create myapp/db secret: %v", err)
	}

	// Nested JSON secret
	_, err = kvClient.Put(ctx, "myapp/config", map[string]any{
		"api_key": "test-api-key-xyz",
		"features": map[string]any{
			"debug":   true,
			"logging": "verbose",
		},
	})
	if err != nil {
		t.Fatalf("failed to create myapp/config secret: %v", err)
	}

	// Secret with special characters
	_, err = kvClient.Put(ctx, "myapp/special", map[string]any{
		"connection_string": "postgres://user:p@ss=word@host:5432/db?sslmode=require",
		"json_field":        `{"nested": "value"}`,
	})
	if err != nil {
		t.Fatalf("failed to create myapp/special secret: %v", err)
	}
}

// INTENTION: VaultBackend.Resolve should retrieve specific fields from a KV v2 secret.
//
//nolint:paralleltest // Integration test sharing container cannot run in parallel
func TestVaultBackend_Resolve(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := t.Context()

	vc := testvault.EnsureVaultContainer(t)
	seedTestSecrets(ctx, t, vc.Address, vc.Token)

	backend := &secrets.VaultBackend{
		Address: vc.Address,
		Token:   vc.Token,
	}

	tests := []struct {
		name     string
		path     string
		fields   []string
		expected map[string]string
	}{
		{
			name:   "simple string fields",
			path:   "secret/myapp/db",
			fields: []string{"username", "password"},
			expected: map[string]string{
				"username": "admin",
				"password": "secret123",
			},
		},
		{
			name:   "numeric field converted to string",
			path:   "secret/myapp/db",
			fields: []string{"port"},
			expected: map[string]string{
				"port": "5432",
			},
		},
		{
			name:   "all fields from secret",
			path:   "secret/myapp/db",
			fields: []string{"username", "password", "host", "port"},
			expected: map[string]string{
				"username": "admin",
				"password": "secret123",
				"host":     "db.example.com",
				"port":     "5432",
			},
		},
		{
			name:   "nested object field marshaled as JSON",
			path:   "secret/myapp/config",
			fields: []string{"features"},
			expected: map[string]string{
				"features": `{"debug":true,"logging":"verbose"}`,
			},
		},
		{
			name:   "special characters in values",
			path:   "secret/myapp/special",
			fields: []string{"connection_string"},
			expected: map[string]string{
				"connection_string": "postgres://user:p@ss=word@host:5432/db?sslmode=require",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.Resolve(ctx, tt.path, tt.fields)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("Resolve() returned %d fields, expected %d", len(result), len(tt.expected))
			}

			for key, expectedValue := range tt.expected {
				actualValue, found := result[key]
				if !found {
					t.Errorf("Field %q not found in result", key)

					continue
				}

				if actualValue != expectedValue {
					t.Errorf("Field %q = %q, expected %q", key, actualValue, expectedValue)
				}
			}
		})
	}
}

// INTENTION: VaultBackend.Resolve should return appropriate errors for invalid inputs.
//
//nolint:paralleltest // Integration test sharing container cannot run in parallel
func TestVaultBackend_Resolve_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := t.Context()

	vc := testvault.EnsureVaultContainer(t)
	seedTestSecrets(ctx, t, vc.Address, vc.Token)

	backend := &secrets.VaultBackend{
		Address: vc.Address,
		Token:   vc.Token,
	}

	tests := []struct {
		name        string
		path        string
		fields      []string
		expectedErr error
	}{
		{
			name:        "empty path",
			path:        "",
			fields:      []string{"username"},
			expectedErr: fault.ErrInvalidArgument,
		},
		{
			name:        "empty fields",
			path:        "secret/myapp/db",
			fields:      []string{},
			expectedErr: fault.ErrNotFound,
		},
		{
			name:        "invalid path format (no mount)",
			path:        "justpath",
			fields:      []string{"username"},
			expectedErr: fault.ErrInvalidArgument,
		},
		{
			name:        "secret not found",
			path:        "secret/nonexistent/path",
			fields:      []string{"username"},
			expectedErr: secrets.ErrVaultSecretNotFound,
		},
		{
			name:        "field not found",
			path:        "secret/myapp/db",
			fields:      []string{"nonexistent_field"},
			expectedErr: fault.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.Resolve(ctx, tt.path, tt.fields)
			if err == nil {
				t.Fatal("Resolve() expected error, got nil")
			}

			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Resolve() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}

// INTENTION: VaultBackend.ResolveDocument should return entire secret as JSON.
//
//nolint:paralleltest // Integration test sharing container cannot run in parallel
func TestVaultBackend_ResolveDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := t.Context()

	vc := testvault.EnsureVaultContainer(t)
	seedTestSecrets(ctx, t, vc.Address, vc.Token)

	backend := &secrets.VaultBackend{
		Address: vc.Address,
		Token:   vc.Token,
	}

	data, err := backend.ResolveDocument(ctx, "secret/myapp/db")
	if err != nil {
		t.Fatalf("ResolveDocument() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal document: %v", err)
	}

	expectedFields := []string{"username", "password", "host", "port"}
	for _, field := range expectedFields {
		if _, found := result[field]; !found {
			t.Errorf("Field %q not found in document", field)
		}
	}

	if result["username"] != "admin" {
		t.Errorf("username = %v, expected admin", result["username"])
	}
}

// INTENTION: VaultBackend should work with environment variable configuration.
func TestVaultBackend_EnvironmentConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := t.Context()

	vc := testvault.EnsureVaultContainer(t)
	seedTestSecrets(ctx, t, vc.Address, vc.Token)

	// Set environment variables
	t.Setenv("VAULT_ADDR", vc.Address)
	t.Setenv("VAULT_TOKEN", vc.Token)

	// Create backend without explicit options (should use env vars)
	backend := &secrets.VaultBackend{}

	result, err := backend.Resolve(ctx, "secret/myapp/db", []string{"username", "password"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if result["username"] != "admin" {
		t.Errorf("username = %q, expected %q", result["username"], "admin")
	}

	if result["password"] != "secret123" {
		t.Errorf("password = %q, expected %q", result["password"], "secret123")
	}
}

// INTENTION: VaultBackend should return ErrVaultNotConfigured when address/token missing.
func TestVaultBackend_NotConfigured(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv()

	// Ensure env vars are not set
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	backend := &secrets.VaultBackend{}

	_, err := backend.Resolve(t.Context(), "secret/test", []string{"field"})
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}

	if !errors.Is(err, secrets.ErrVaultNotConfigured) {
		t.Errorf("Resolve() error = %v, expected %v", err, secrets.ErrVaultNotConfigured)
	}
}

// INTENTION: VaultBackend should return ErrVaultUnavailable when server is unreachable.
func TestVaultBackend_Unavailable(t *testing.T) {
	t.Parallel()

	backend := &secrets.VaultBackend{
		Address: "http://localhost:1", // Unreachable port
		Token:   "fake-token",
	}

	_, err := backend.Resolve(t.Context(), "secret/test", []string{"field"})
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}

	if !errors.Is(err, secrets.ErrVaultUnavailable) {
		t.Errorf("Resolve() error = %v, expected %v", err, secrets.ErrVaultUnavailable)
	}
}

// INTENTION: VaultBackend should return ErrVaultPermissionDenied with invalid token.
//
//nolint:paralleltest // Integration test using container cannot run in parallel
func TestVaultBackend_PermissionDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := t.Context()

	vc := testvault.EnsureVaultContainer(t)

	backend := &secrets.VaultBackend{
		Address: vc.Address,
		Token:   "invalid-token",
	}

	_, err := backend.Resolve(ctx, "secret/myapp/db", []string{"username"})
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}

	if !errors.Is(err, secrets.ErrVaultPermissionDenied) {
		t.Errorf("Resolve() error = %v, expected %v", err, secrets.ErrVaultPermissionDenied)
	}
}
