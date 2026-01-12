package dockle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/farcloser/quark/internal/types"
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
	creds *types.RegistryCredentials,
) (*ScanResult, error) {
	// Build dockle command
	args := []string{"--format", "json", "--exit-code", "1", "--timeout", "120s", imageRef}

	//nolint:gosec // Image ref is from user config
	cmd := exec.CommandContext(ctx, scanner.docklePath, args...)

	// Initialize environment with parent variables
	cmd.Env = os.Environ()

	// Set credentials via environment variables to avoid exposing in process list
	// DOCKLE_AUTH_URL scopes credentials to the specific registry
	if creds != nil && creds.Username != "" && creds.Password != "" && creds.Domain != "" {
		cmd.Env = append(cmd.Env,
			"DOCKLE_AUTH_URL=https://"+creds.Domain,
			"DOCKLE_USERNAME="+creds.Username,
			"DOCKLE_PASSWORD="+creds.Password,
		)
	}

	// Capture stdout and stderr separately - dockle outputs JSON to stdout
	// but may print progress/warnings to stderr
	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Parse dockle JSON output from stdout only
	dockleResult := &ScanResult{}
	if stdout.Len() > 0 {
		if parseErr := json.Unmarshal(stdout.Bytes(), dockleResult); parseErr != nil {
			return nil, fmt.Errorf("%w: %w (stdout: %s)", ErrParsingFailed, parseErr, stdout.String())
		}
	} else if err != nil {
		// Command failed with no stdout - include stderr in error
		return nil, fmt.Errorf("%w: %w (stderr: %s)", ErrScanFailed, err, stderr.String())
	}

	return dockleResult, nil
}
