package secrets

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

// OnePasswordBackend implements secret resolution using 1Password CLI.
type OnePasswordBackend struct{}

// NewOnePasswordBackend creates a new 1Password backend.
func NewOnePasswordBackend() *OnePasswordBackend {
	return &OnePasswordBackend{}
}

// Scheme returns the URI scheme for 1Password ("op").
func (*OnePasswordBackend) Scheme() string {
	return "op"
}

// Resolve retrieves secrets from 1Password.
// Path format: "vault/item"
// Fields: list of field names to extract from the item.
func (*OnePasswordBackend) Resolve(ctx context.Context, path string, fields []string) (map[string]string, error) {
	if path == "" {
		return nil, ErrReferenceEmpty
	}

	if len(fields) == 0 {
		return nil, ErrFieldsEmpty
	}

	// Parse item reference: vault/item
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w (expected 'vault/item'): %q", ErrReferenceInvalidFormat, path)
	}

	vault := parts[0]
	item := parts[1]

	if vault == "" || item == "" {
		return nil, fmt.Errorf("%w: %q", ErrReferenceEmptyParts, path)
	}

	// Get the entire item as JSON
	//nolint:gosec // G204: Variables are from parsed/validated reference, passed as separate args (no shell injection)
	cmd := exec.CommandContext(ctx, opCLI, "item", "get", item, "--vault", vault, "--format", "json")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get item: %w (check 1Password authentication)", err)
	}

	// Parse JSON response
	var itemData opItemResponse

	if err := json.Unmarshal(output, &itemData); err != nil {
		return nil, fmt.Errorf("failed to parse item JSON: %w (check item format in 1Password)", err)
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
			return nil, fmt.Errorf("%w: %q", ErrFieldNotFound, fieldName)
		}

		result[fieldName] = value
	}

	return result, nil
}

// ResolveDocument retrieves raw document/file content from 1Password.
// Path format: "vault/item" for standalone documents, or "vault/item/filename" for file attachments.
// Uses `op read` with secret references to retrieve content, which works for both
// standalone Document items and file attachments on regular items.
func (*OnePasswordBackend) ResolveDocument(ctx context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, ErrReferenceEmpty
	}

	// Validate path has at least vault/item
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"%w (expected 'vault/item' or 'vault/item/filename'): %q",
			ErrReferenceInvalidFormat,
			path,
		)
	}

	// Use op read with secret reference format
	// This works for both Document items (op://vault/document) and
	// file attachments on items (op://vault/item/filename)
	secretRef := "op://" + path

	//nolint:gosec // G204: secretRef is constructed from validated path, passed as single arg (no shell injection)
	cmd := exec.CommandContext(ctx, opCLI, "read", secretRef)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w (check 1Password authentication)", err)
	}

	if len(output) == 0 {
		return nil, ErrDocumentEmpty
	}

	return output, nil
}
