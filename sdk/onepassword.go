package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

const (
	// opCLI is the 1Password CLI command name.
	opCLI = "op"
)

// opField represents a field in a 1Password item.
type opField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// opItemResponse represents the JSON response from `op item get --format json`.
type opItemResponse struct {
	Fields []opField `json:"fields"`
}

// AuthenticateOp pre-authenticates with 1Password CLI to establish a session.
// This should be called before making parallel GetSecret/GetSecretDocument calls
// to prevent multiple biometric authentication prompts.
//
// Uses `op signin` which is idempotent - it only prompts for authentication
// if not already authenticated. Requires 1Password desktop app integration.
func AuthenticateOp(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, opCLI, "signin")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to authenticate with 1Password: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// GetSecretDocument retrieves a document from 1Password using a document reference.
// Reference format: "op://vault/item"
//
// Example:
//
//	content, err := GetSecretDocument(ctx, "op://Security (office)/scimsession file")
//
// Uses the 1Password CLI (`op document get`) which supports:
// - Interactive authentication via `op signin` (local development)
// - Service account tokens via OP_SERVICE_ACCOUNT_TOKEN (CI/CD)
// - Desktop app integration with biometric authentication
// - Vault names with spaces and special characters (e.g., parentheses)
//
// Returns the raw document content as bytes.
// Requires the `op` CLI to be installed and authenticated.
func GetSecretDocument(ctx context.Context, reference string) ([]byte, error) {
	if reference == "" {
		return nil, ErrDocumentReferenceEmpty
	}

	// Parse document reference: op://vault/item
	if !strings.HasPrefix(reference, "op://") {
		return nil, fmt.Errorf("%w: %q", ErrDocumentReferenceInvalidPrefix, reference)
	}

	parts := strings.SplitN(strings.TrimPrefix(reference, "op://"), "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w (expected 'op://vault/item'): %q", ErrDocumentReferenceInvalidFormat, reference)
	}

	vault := parts[0]
	item := parts[1]

	if vault == "" || item == "" {
		return nil, fmt.Errorf("%w: %q", ErrDocumentReferenceEmptyParts, reference)
	}

	// Use op document get for retrieving document content
	//nolint:gosec // G204: Variables are from parsed/validated reference, passed as separate args (no shell injection)
	cmd := exec.CommandContext(ctx, opCLI, "document", "get", item, "--vault", vault)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get document %q: %w\nOutput: %s", reference, err, string(output))
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrDocumentEmpty, reference)
	}

	return output, nil
}

// GetSecret retrieves multiple fields from a 1Password item in a single call.
// Reference format: "op://vault/item"
//
// Example:
//
//	secrets, err := GetSecret(ctx, "op://Security (build)/deploy.registry.rw",
//	    []string{"organization", "username", "password", "domain"})
//	registryOrg := secrets["organization"]
//	registryUser := secrets["username"]
//
// Retrieves the entire item once and extracts the requested fields efficiently.
//
// Uses the 1Password CLI (`op item get --format json`) which supports:
// - Interactive authentication via `op signin` (local development)
// - Service account tokens via OP_SERVICE_ACCOUNT_TOKEN (CI/CD)
// - Desktop app integration with biometric authentication
// - Vault names with spaces and special characters (e.g., parentheses)
//
// Returns a map of field names to their string values.
// Returns an error if any requested field is not found in the item.
// Requires the `op` CLI to be installed and authenticated.
func GetSecret(ctx context.Context, itemRef string, fields []string) (map[string]string, error) {
	if itemRef == "" {
		return nil, ErrItemReferenceEmpty
	}

	if len(fields) == 0 {
		return nil, ErrItemFieldsEmpty
	}

	// Parse item reference: op://vault/item
	if !strings.HasPrefix(itemRef, "op://") {
		return nil, fmt.Errorf("%w: %q", ErrItemReferenceInvalidPrefix, itemRef)
	}

	parts := strings.SplitN(strings.TrimPrefix(itemRef, "op://"), "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w (expected 'op://vault/item'): %q", ErrItemReferenceInvalidFormat, itemRef)
	}

	vault := parts[0]
	item := parts[1]

	if vault == "" || item == "" {
		return nil, fmt.Errorf("%w: %q", ErrItemReferenceEmptyParts, itemRef)
	}

	// Get the entire item as JSON
	//nolint:gosec // G204: Variables are from parsed/validated reference, passed as separate args (no shell injection)
	cmd := exec.CommandContext(ctx, opCLI, "item", "get", item, "--vault", vault, "--format", "json")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get item %q: %w\nOutput: %s", itemRef, err, string(output))
	}

	// Parse JSON response
	var itemData opItemResponse

	if err := json.Unmarshal(output, &itemData); err != nil {
		return nil, fmt.Errorf("failed to parse item JSON for %q: %w", itemRef, err)
	}

	// Build field map
	fieldMap := make(map[string]string)
	for _, field := range itemData.Fields {
		fieldMap[field.Label] = field.Value
	}

	// Extract requested fields
	result := make(map[string]string)

	for _, fieldName := range fields {
		value, found := fieldMap[fieldName]
		if !found {
			return nil, fmt.Errorf("%w: %q in item %q", ErrItemFieldNotFound, fieldName, itemRef)
		}

		result[fieldName] = value
	}

	return result, nil
}
