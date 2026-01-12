package secrets_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/internal/secrets"
)

// ageTestEnv holds test environment state for age backend tests.
type ageTestEnv struct {
	tmpDir       string
	identityPath string
	identity     *age.X25519Identity
}

// setupAgeTestEnv creates a test environment with identity and encrypted files.
func setupAgeTestEnv(t *testing.T) *ageTestEnv {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	tmpDir := t.TempDir()

	identityPath := filepath.Join(tmpDir, "identity.txt")
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	return &ageTestEnv{
		tmpDir:       tmpDir,
		identityPath: identityPath,
		identity:     identity,
	}
}

// newBackend creates an AgeBackend with the test identity.
func (e *ageTestEnv) newBackend(t *testing.T) *secrets.AgeBackend {
	t.Helper()

	backend, err := (&secrets.AgeConfig{Identity: e.identity.String()}).CreateBackend(t.Context())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	return backend.(*secrets.AgeBackend)
}

// encryptFile encrypts content to a file using the test identity.
func (e *ageTestEnv) encryptFile(t *testing.T, filename string, content []byte) string {
	t.Helper()

	encryptedPath := filepath.Join(e.tmpDir, filename)
	recipient := e.identity.Recipient()

	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}

	w, err := age.Encrypt(encryptedFile, recipient)
	if err != nil {
		_ = encryptedFile.Close()

		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if _, err := w.Write(content); err != nil {
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

	return encryptedPath
}

// INTENTION: AgeBackend.Resolve should retrieve specific fields from encrypted JSON files.
//
//nolint:paralleltest // Uses t.Chdir which is incompatible with parallel tests
func TestAgeBackend_Resolve(t *testing.T) {
	env := setupAgeTestEnv(t)

	secretJSON := `{
		"database": {
			"host": "localhost",
			"password": "secret123",
			"port": 5432
		},
		"api_key": "test-key-123",
		"nested": {
			"deep": {
				"value": "deeply-nested"
			}
		}
	}`

	env.encryptFile(t, "secrets.json.age", []byte(secretJSON))

	t.Chdir(env.tmpDir)

	tests := []struct {
		name     string
		path     string
		fields   []string
		expected map[string]string
	}{
		{
			name:   "extract from root",
			path:   "secrets.json.age",
			fields: []string{"api_key"},
			expected: map[string]string{
				"api_key": "test-key-123",
			},
		},
		{
			name:   "navigate to nested object",
			path:   "secrets.json.age/database",
			fields: []string{"host", "password"},
			expected: map[string]string{
				"host":     "localhost",
				"password": "secret123",
			},
		},
		{
			name:   "extract all fields from nested object",
			path:   "secrets.json.age/database",
			fields: []string{"host", "password", "port"},
			expected: map[string]string{
				"host":     "localhost",
				"password": "secret123",
				"port":     "5432",
			},
		},
		{
			name:   "deeply nested navigation",
			path:   "secrets.json.age/nested/deep",
			fields: []string{"value"},
			expected: map[string]string{
				"value": "deeply-nested",
			},
		},
		{
			name:   "nested object field marshaled as JSON",
			path:   "secrets.json.age",
			fields: []string{"database"},
			expected: map[string]string{
				"database": `{"host":"localhost","password":"secret123","port":5432}`,
			},
		},
	}

	backend := env.newBackend(t)
	ctx := t.Context()

	//nolint:paralleltest // Cannot use t.Parallel in subtests when parent uses t.Setenv/t.Chdir
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

// INTENTION: AgeBackend.Resolve should return appropriate errors for invalid inputs.
//
//nolint:paralleltest // Uses t.Chdir which is incompatible with parallel tests
func TestAgeBackend_Resolve_Errors(t *testing.T) {
	env := setupAgeTestEnv(t)

	secretJSON := `{"username": "admin", "password": "secret"}`
	env.encryptFile(t, "secrets.json.age", []byte(secretJSON))

	t.Chdir(env.tmpDir)

	backend := env.newBackend(t)
	ctx := t.Context()

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
			path:        "secrets.json.age",
			fields:      []string{},
			expectedErr: fault.ErrNotFound,
		},
		{
			name:        "file not found",
			path:        "nonexistent.json.age",
			fields:      []string{"username"},
			expectedErr: fault.ErrNotFound,
		},
		{
			name:        "field not found",
			path:        "secrets.json.age",
			fields:      []string{"nonexistent_field"},
			expectedErr: fault.ErrNotFound,
		},
		{
			name:        "invalid JSON path",
			path:        "secrets.json.age/nonexistent/path",
			fields:      []string{"username"},
			expectedErr: fault.ErrNotFound,
		},
	}

	//nolint:paralleltest // Cannot use t.Parallel in subtests when parent uses t.Setenv/t.Chdir
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

// INTENTION: AgeBackend.ResolveDocument should return raw decrypted content.
//
//nolint:paralleltest // Uses t.Chdir which is incompatible with parallel tests
func TestAgeBackend_ResolveDocument(t *testing.T) {
	env := setupAgeTestEnv(t)

	// Test with JSON content
	jsonContent := `{"key": "value", "number": 42}`
	env.encryptFile(t, "config.json.age", []byte(jsonContent))

	// Test with non-JSON content (e.g., SSH key)
	sshKey := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBbeWxsdjlKQUFvM3FBK0dYc1hKM1VQL3hITjBPL3hzTjBBPT0AAAAA
-----END OPENSSH PRIVATE KEY-----`
	env.encryptFile(t, "deploy-key.age", []byte(sshKey))

	t.Chdir(env.tmpDir)

	backend := env.newBackend(t)
	ctx := t.Context()

	t.Run("json document", func(t *testing.T) {
		data, err := backend.ResolveDocument(ctx, "config.json.age")
		if err != nil {
			t.Fatalf("ResolveDocument() error = %v", err)
		}

		if string(data) != jsonContent {
			t.Errorf("ResolveDocument() = %q, expected %q", string(data), jsonContent)
		}
	})

	t.Run("non-json document", func(t *testing.T) {
		data, err := backend.ResolveDocument(ctx, "deploy-key.age")
		if err != nil {
			t.Fatalf("ResolveDocument() error = %v", err)
		}

		if string(data) != sshKey {
			t.Errorf("ResolveDocument() = %q, expected %q", string(data), sshKey)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := backend.ResolveDocument(ctx, "nonexistent.age")
		if err == nil {
			t.Fatal("ResolveDocument() expected error, got nil")
		}

		if !errors.Is(err, fault.ErrNotFound) {
			t.Errorf("ResolveDocument() error = %v, expected %v", err, fault.ErrNotFound)
		}
	})
}

// INTENTION: AgeConfig should fail with empty identity.
func TestAgeConfig_EmptyIdentity(t *testing.T) {
	t.Parallel()

	// Create backend with empty identity should fail
	_, err := (&secrets.AgeConfig{Identity: ""}).CreateBackend(t.Context())
	if err == nil {
		t.Fatal("CreateBackend() expected error, got nil")
	}
}

// INTENTION: AgeBackend should return ErrNoMatchingIdentity when wrong key is used.
//
//nolint:paralleltest // Uses t.Chdir which is incompatible with parallel tests
func TestAgeBackend_WrongIdentity(t *testing.T) {
	// Create two different identities
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity1: %v", err)
	}

	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity2: %v", err)
	}

	tmpDir := t.TempDir()

	// Encrypt with identity1's recipient (identity2 won't be able to decrypt)
	encryptedPath := filepath.Join(tmpDir, "secrets.json.age")

	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}

	w, err := age.Encrypt(encryptedFile, identity1.Recipient())
	if err != nil {
		_ = encryptedFile.Close()

		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if _, err := w.Write([]byte(`{"key": "value"}`)); err != nil {
		_ = w.Close()
		_ = encryptedFile.Close()

		t.Fatalf("Failed to write encrypted data: %v", err)
	}

	_ = w.Close()
	_ = encryptedFile.Close()

	t.Chdir(tmpDir)

	// Create backend with identity2 (wrong key for decryption)
	backend, err := (&secrets.AgeConfig{Identity: identity2.String()}).CreateBackend(t.Context())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	_, err = backend.Resolve(t.Context(), "secrets.json.age", []string{"key"})
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}

	if !errors.Is(err, secrets.ErrNoMatchingIdentity) {
		t.Errorf("Resolve() error = %v, expected %v", err, secrets.ErrNoMatchingIdentity)
	}
}

// INTENTION: AgeBackend should return ErrInvalidJSON when decrypted content is not valid JSON.
//
//nolint:paralleltest // Uses t.Chdir which is incompatible with parallel tests
func TestAgeBackend_InvalidJSON(t *testing.T) {
	env := setupAgeTestEnv(t)

	// Encrypt invalid JSON
	env.encryptFile(t, "invalid.json.age", []byte("this is not json"))

	t.Chdir(env.tmpDir)

	backend := env.newBackend(t)

	_, err := backend.Resolve(t.Context(), "invalid.json.age", []string{"field"})
	if err == nil {
		t.Fatal("Resolve() expected error, got nil")
	}

	if !errors.Is(err, fault.ErrInvalidJSON) {
		t.Errorf("Resolve() error = %v, expected %v", err, fault.ErrInvalidJSON)
	}
}

// INTENTION: AgeBackend should handle special characters in values.
//
//nolint:paralleltest,gosmopolitan // Uses t.Chdir; unicode test data is intentional
func TestAgeBackend_SpecialCharacters(t *testing.T) {
	env := setupAgeTestEnv(t)

	secretJSON := `{
		"connection_string": "postgres://user:p@ss=word@host:5432/db?sslmode=require",
		"unicode": "日本語テスト",
		"multiline": "line1\nline2\nline3",
		"escaped": "tab\there, quote\"here"
	}`

	env.encryptFile(t, "special.json.age", []byte(secretJSON))

	t.Chdir(env.tmpDir)

	backend := env.newBackend(t)
	ctx := t.Context()

	result, err := backend.Resolve(ctx, "special.json.age", []string{
		"connection_string",
		"unicode",
		"multiline",
		"escaped",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	expected := map[string]string{
		"connection_string": "postgres://user:p@ss=word@host:5432/db?sslmode=require",
		"unicode":           "日本語テスト",
		"multiline":         "line1\nline2\nline3",
		"escaped":           "tab\there, quote\"here",
	}

	for key, expectedValue := range expected {
		if result[key] != expectedValue {
			t.Errorf("Field %q = %q, expected %q", key, result[key], expectedValue)
		}
	}
}
