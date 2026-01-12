package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/farcloser/quark/dev/fault"
)

// AgeBackend implements secret resolution using age encryption.
type AgeBackend struct {
	identities []age.Identity
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
		return nil, fault.ErrInvalidArgument
	}

	if len(fields) == 0 {
		return nil, fault.ErrNotFound
	}

	// Split on first .age to separate file path from JSON path
	filePath, jsonPath := b.parseURI(path)

	if len(b.identities) == 0 {
		return nil, ErrIdentityNotSet
	}

	// Decrypt file
	decrypted, err := b.decryptFile(filePath, b.identities)
	if err != nil {
		return nil, err
	}

	// Parse JSON
	var data any
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
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
		return nil, fault.ErrInvalidArgument
	}

	// For document retrieval, we just need the file path (no JSON navigation)
	filePath, _ := b.parseURI(path)

	if len(b.identities) == 0 {
		return nil, ErrIdentityNotSet
	}

	// Decrypt and return raw content
	return b.decryptFile(filePath, b.identities)
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

// decryptFile decrypts an age-encrypted file.
// Path is resolved relative to current working directory.
func (*AgeBackend) decryptFile(filePath string, identities []age.Identity) ([]byte, error) {
	//nolint:gosec // Path from plan configuration, user-controlled
	encryptedFile, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", fault.ErrNotFound, filePath)
		}

		return nil, fmt.Errorf("%w: %s: %w", fault.ErrFilesystemFailure, filePath, err)
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
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
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
			return nil, fmt.Errorf("%w: path %q not found (not an object)", fault.ErrNotFound, path)
		}

		next, found := m[part]
		if !found {
			return nil, fmt.Errorf("%w: key %q not found in path %q", fault.ErrNotFound, part, path)
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
		return nil, fmt.Errorf("%w: resolved data is not an object", fault.ErrNotFound)
	}

	for _, fieldName := range fields {
		value, found := dataMap[fieldName]
		if !found {
			return nil, fmt.Errorf("%w: %q", fault.ErrNotFound, fieldName)
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
				return nil, fmt.Errorf("%w %q: %w", fault.ErrInvalidJSON, fieldName, err)
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
