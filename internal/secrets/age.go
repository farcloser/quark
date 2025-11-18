package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// AgeBackend implements secret resolution using age encryption.
type AgeBackend struct{}

// NewAgeBackend creates a new age backend.
func NewAgeBackend() *AgeBackend {
	return &AgeBackend{}
}

// Scheme returns the URI scheme for age ("age").
func (*AgeBackend) Scheme() string {
	return "age"
}

// Resolve retrieves secrets from age-encrypted files.
// Path format: "path/to/file.age[/json/path]"
// Examples:
//   - "secrets/db.json.age" - entire file
//   - "secrets/db.json.age/prod" - navigate to "prod" key
//   - "secrets/db.json.age/prod/credentials" - deep navigation
//
// Paths are resolved relative to current working directory.
// Fields: list of field names to extract from the resolved JSON subtree.
func (b *AgeBackend) Resolve(_ context.Context, path string, fields []string) (map[string]string, error) {
	if path == "" {
		return nil, ErrReferenceEmpty
	}

	if len(fields) == 0 {
		return nil, ErrFieldsEmpty
	}

	// Split on first .age to separate file path from JSON path
	filePath, jsonPath := b.parseURI(path)

	// Load identities
	identities, err := b.loadIdentities()
	if err != nil {
		return nil, err
	}

	// Decrypt file
	decrypted, err := b.decryptFile(filePath, identities)
	if err != nil {
		return nil, err
	}

	// Parse JSON
	var data any
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}

	// Navigate JSON path if provided
	if jsonPath != "" {
		data, err = b.navigateJSON(data, jsonPath)
		if err != nil {
			return nil, err
		}
	}

	// Extract fields
	return b.extractFields(data, fields)
}

// ResolveDocument retrieves raw decrypted content from age-encrypted files.
// Path format: "path/to/file.age"
// Returns the raw decrypted content without any JSON parsing.
func (b *AgeBackend) ResolveDocument(_ context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, ErrReferenceEmpty
	}

	// For document retrieval, we just need the file path (no JSON navigation)
	filePath, _ := b.parseURI(path)

	// Load identities
	identities, err := b.loadIdentities()
	if err != nil {
		return nil, err
	}

	// Decrypt and return raw content
	return b.decryptFile(filePath, identities)
}

// Example: "secrets/db.json.age/prod/credentials" -> ("secrets/db.json.age", "prod/credentials").
func (*AgeBackend) parseURI(uriPath string) (filePath, jsonPath string) {
	// Find the first occurrence of .age
	ageIndex := strings.Index(uriPath, ".age")
	if ageIndex == -1 {
		// No .age extension found, treat entire path as file path
		return uriPath, ""
	}

	// File path includes .age extension
	filePath = uriPath[:ageIndex+4] // +4 for ".age"

	// Check if there's a JSON path after .age
	if len(uriPath) > ageIndex+4 && uriPath[ageIndex+4] == '/' {
		jsonPath = strings.TrimPrefix(uriPath[ageIndex+4:], "/")
	}

	return filePath, jsonPath
}

// loadIdentities loads age identities from HADRON_AGE_IDENTITY environment variable.
func (*AgeBackend) loadIdentities() ([]age.Identity, error) {
	identityPath := os.Getenv("HADRON_AGE_IDENTITY")
	if identityPath == "" {
		return nil, ErrIdentityNotSet
	}

	// Expand ~ to home directory
	if strings.HasPrefix(identityPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}

		identityPath = filepath.Join(home, identityPath[2:])
	}

	//nolint:gosec // Path from environment variable, user-controlled
	identityFile, err := os.Open(identityPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrIdentityNotFound, identityPath)
		}

		return nil, fmt.Errorf("failed to open identity file: %w", err)
	}

	defer func() { _ = identityFile.Close() }()

	identities, err := age.ParseIdentities(identityFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentityNotFound, err)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrIdentityNotFound, identityPath)
	}

	return identities, nil
}

// decryptFile decrypts an age-encrypted file.
// Path is resolved relative to current working directory.
func (*AgeBackend) decryptFile(filePath string, identities []age.Identity) ([]byte, error) {
	//nolint:gosec // Path from plan configuration, user-controlled
	encryptedFile, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrFileNotFound, filePath)
		}

		return nil, fmt.Errorf("failed to open encrypted file: %w", err)
	}

	defer func() { _ = encryptedFile.Close() }()

	reader, err := age.Decrypt(encryptedFile, identities...)
	if err != nil {
		if strings.Contains(err.Error(), "no identity matched") {
			return nil, ErrNoMatchingIdentity
		}

		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted content: %w", err)
	}

	return decrypted, nil
}

// Example: "prod/credentials" navigates to data["prod"]["credentials"].
func (*AgeBackend) navigateJSON(data any, path string) (any, error) {
	parts := strings.Split(path, "/")

	current := data

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Navigate into the next level
		m, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: path %q not found (not an object)", ErrFieldNotFound, path)
		}

		next, found := m[part]
		if !found {
			return nil, fmt.Errorf("%w: key %q not found in path %q", ErrFieldNotFound, part, path)
		}

		current = next
	}

	return current, nil
}

// extractFields extracts requested fields from a JSON value.
func (*AgeBackend) extractFields(data any, fields []string) (map[string]string, error) {
	result := make(map[string]string)

	// If data is a map, extract fields from it
	dataMap, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: resolved data is not an object", ErrFieldNotFound)
	}

	for _, fieldName := range fields {
		value, found := dataMap[fieldName]
		if !found {
			return nil, fmt.Errorf("%w: %q", ErrFieldNotFound, fieldName)
		}

		// Convert value to string
		var strValue string
		switch typedValue := value.(type) {
		case string:
			strValue = typedValue
		case map[string]any, []any:
			// For complex types, marshal back to JSON
			jsonBytes, err := json.Marshal(typedValue)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal field %q: %w", fieldName, err)
			}

			strValue = string(jsonBytes)
		default:
			// For other types (numbers, booleans), use fmt.Sprint
			strValue = fmt.Sprint(typedValue)
		}

		result[fieldName] = strValue
	}

	return result, nil
}
