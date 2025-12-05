package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/farcloser/quark/kit/secrets"
)

func TestAgeBackend(t *testing.T) {
	// Generate a test identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Create identity file
	identityPath := filepath.Join(tmpDir, "identity.txt")
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	// Set environment variable
	t.Setenv("HADRON_AGE_IDENTITY", identityPath)

	// Create test secret data
	//nolint:gosec // G101: Test data with intentional hardcoded credentials
	secretJSON := `{
		"database": {
			"host": "localhost",
			"password": "secret123",
			"port": 5432
		},
		"api_key": "test-key-123"
	}`

	// Encrypt the secret
	encryptedPath := filepath.Join(tmpDir, "secrets.json.age")
	recipient := identity.Recipient()

	//nolint:gosec // G304: Test file path in temporary directory
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}

	w, err := age.Encrypt(encryptedFile, recipient)
	if err != nil {
		_ = encryptedFile.Close()

		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if _, err := w.Write([]byte(secretJSON)); err != nil {
		_ = w.Close()
		_ = encryptedFile.Close()

		t.Fatalf("Failed to write encrypted data: %v", err)
	}

	if err := w.Close(); err != nil {
		_ = encryptedFile.Close()

		t.Fatalf("Failed to close encryptor: %v", err)
	}

	if err := encryptedFile.Close(); err != nil {
		t.Fatalf("Failed to close encrypted file: %v", err)
	}

	// Change to tmpDir so relative paths work
	t.Chdir(tmpDir)

	// Test cases
	tests := []struct {
		name     string
		path     string
		fields   []string
		expected map[string]string
	}{
		{
			name:   "Extract from root",
			path:   "secrets.json.age",
			fields: []string{"api_key"},
			expected: map[string]string{
				"api_key": "test-key-123",
			},
		},
		{
			name:   "Navigate to nested object",
			path:   "secrets.json.age/database",
			fields: []string{"host", "password"},
			expected: map[string]string{
				"host":     "localhost",
				"password": "secret123",
			},
		},
		{
			name:   "Extract all fields from nested object",
			path:   "secrets.json.age/database",
			fields: []string{"host", "password", "port"},
			expected: map[string]string{
				"host":     "localhost",
				"password": "secret123",
				"port":     "5432",
			},
		},
	}

	backend := secrets.NewAgeBackend()
	ctx := t.Context()

	//nolint:paralleltest // Cannot use t.Parallel in subtests when parent uses t.Setenv/t.Chdir
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.Resolve(ctx, tt.path, tt.fields)
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d fields, got %d", len(tt.expected), len(result))
			}

			for key, expectedValue := range tt.expected {
				actualValue, found := result[key]
				if !found {
					t.Errorf("Field %q not found in result", key)

					continue
				}

				if actualValue != expectedValue {
					t.Errorf("Field %q: expected %q, got %q", key, expectedValue, actualValue)
				}
			}
		})
	}
}
