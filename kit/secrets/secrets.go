package secrets

import (
	"context"
	"fmt"
	"os/exec"
)

// AuthenticateOp pre-authenticates with 1Password CLI to establish a session.
// This should be called before making parallel Get/GetDocument calls
// to prevent multiple biometric authentication prompts.
//
// Uses `op signin` which is idempotent - it only prompts for authentication
// if not already authenticated. Requires 1Password desktop app integration.
func AuthenticateOp(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, opCLI, "signin")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to authenticate with 1Password: %w (check 1Password authentication)", err)
	}

	return nil
}

// GetDocument retrieves raw document content using a pluggable backend system.
// Supports multiple URI schemes:
//   - "op://vault/item" - 1Password document
//   - "age://path/to/file.age" - age encrypted file (raw decrypted content)
//
// Examples:
//
//	// 1Password document
//	content, err := GetDocument(ctx, "op://Security (office)/scimsession file")
//
//	// Age encrypted SSH key
//	sshKey, err := GetDocument(ctx, "age://secrets/deploy-key.age")
//
// Returns the raw document content as bytes (no JSON parsing).
func GetDocument(ctx context.Context, uri string) ([]byte, error) {
	return defaultResolver.ResolveDocument(ctx, uri)
}

// Get retrieves specific fields from a secret identified by URI.
// Supports multiple URI schemes:
//   - "op://vault/item" - 1Password
//   - "age://path/to/file.age[/json/path]" - age encryption
//
// Examples:
//
//	// 1Password
//	secrets, err := Get(ctx, "op://Security (build)/deploy.registry.rw",
//	    []string{"organization", "username", "password"})
//
//	// Age encryption
//	secrets, err := Get(ctx, "age://secrets/db.json.age/prod",
//	    []string{"host", "password"})
//
// Returns a map of field names to their string values.
func Get(ctx context.Context, uri string, fields []string) (map[string]string, error) {
	return defaultResolver.Resolve(ctx, uri, fields)
}

//nolint:gochecknoglobals
var defaultResolver = initDefaultResolver()

func initDefaultResolver() *Resolver {
	resolver := NewResolver()
	resolver.Register(NewOnePasswordBackend())
	resolver.Register(NewAgeBackend())

	return resolver
}
