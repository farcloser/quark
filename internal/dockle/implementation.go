package dockle

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/farcloser/quark/internal/utilities"
)

// Scanner wraps Dockle CLI operations.
type dockleScanner struct {
	log        *slog.Logger
	docklePath string
}

// ScanImage scans an image with dockle.
func (scanner *dockleScanner) ScanImage(
	ctx context.Context,
	imageRef string,
	creds *utilities.RegistryCredentials,
) (*ScanResult, error) {
	// Build dockle command
	args := []string{"--format", "json", "--exit-code", "1", imageRef}

	//nolint:gosec // Image ref is from user config
	cmd := exec.CommandContext(ctx, scanner.docklePath, args...)

	// Initialize environment with parent variables
	cmd.Env = os.Environ()

	// Set credentials via environment variables to avoid exposing in process list
	// DOCKLE_AUTH_URL scopes credentials to the specific registry
	if creds != nil && creds.Username != "" && creds.Token != "" && creds.Domain != "" {
		cmd.Env = append(cmd.Env,
			"DOCKLE_AUTH_URL=https://"+creds.Domain,
			"DOCKLE_USERNAME="+creds.Username,
			"DOCKLE_PASSWORD="+creds.Token,
		)
	}

	output, err := cmd.CombinedOutput()

	// Parse dockle JSON output
	dockleResult := &ScanResult{}
	if len(output) > 0 {
		if parseErr := json.Unmarshal(output, dockleResult); parseErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrParsingFailed, parseErr)
		}
	} else if err != nil {
		// Command failed with no output
		return nil, fmt.Errorf("%w: %w", ErrScanFailed, err)
	}

	return dockleResult, nil
}
