// Package main provides the Quark CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/farcloser/quark/dev/filesystem"
	"github.com/farcloser/quark/dev/trust"
	"github.com/farcloser/quark/dev/version"
	"github.com/farcloser/quark/kit/defaults"
)

var (
	errPlanFileNotFound = errors.New("plan file not found")
	errFileExists       = errors.New("file already exists")
)

func main() {
	ctx := context.Background()
	// SetDefaultsForLogger zerolog with LOG_LEVEL env var support
	defaults.SetDefaultsForLogger(ctx)

	cmd := &cli.Command{
		Name:    version.Name,
		Usage:   "Container image management tool",
		Version: version.Version,
		Commands: []*cli.Command{
			{
				Name:  "execute",
				Usage: "Execute a plan file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "plan",
						Aliases:  []string{"p"},
						Usage:    "Path to plan file",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "dry-run",
						Usage:   "Simulate execution without making changes",
						Aliases: []string{"n"},
					},
					&cli.StringFlag{
						Name:  "trace",
						Usage: "Generate execution trace waterfall as DOT file at specified path",
					},
				},
				Action: executeCommand,
			},
			{
				Name:  "debug",
				Usage: "Export plan dependency graph as DOT format (pipe to: | dot -Tsvg > graph.svg)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "plan",
						Aliases:  []string{"p"},
						Usage:    "Path to plan file",
						Required: true,
					},
				},
				Action: debugCommand,
			},
			{
				Name:  "generate-key-pair",
				Usage: "Generate a cosign-compatible signing key pair",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file prefix (creates <prefix>.key and <prefix>.pub)",
						Value:   "cosign",
					},
				},
				Action: generateKeyPairCommand,
			},
		},
	}

	if err := cmd.Run(ctx, os.Args); err != nil {
		log.Fatal().Err(err).Msg("command failed")
	}
}

func executeCommand(ctx context.Context, cmd *cli.Command) error {
	planPath := cmd.String("plan")
	dryRun := cmd.Bool("dry-run")
	tracePath := cmd.String("trace")

	// Determine if planPath is a directory or file
	stat, err := os.Stat(planPath)
	if err != nil {
		return fmt.Errorf("%w: %s", errPlanFileNotFound, planPath)
	}

	var (
		planDir string
		args    []string
	)

	if stat.IsDir() {
		// Directory: go run .
		planDir = planPath
		args = []string{"run", "."}
	} else {
		// File: go run basename
		planDir = filepath.Dir(planPath)
		args = []string{"run", filepath.Base(planPath)}
	}

	// Set environment variables for plan execution
	if dryRun {
		if err := os.Setenv("QUARK_DRY_RUN", "true"); err != nil {
			return fmt.Errorf("failed to set DRY_RUN env: %w", err)
		}
	}

	if tracePath != "" {
		if err := os.Setenv("QUARK_TRACE", tracePath); err != nil {
			return fmt.Errorf("failed to set QUARK_TRACE env: %w", err)
		}
	}

	// #nosec G204 -- args constructed from validated plan path, executing go run is intentional
	execCmd := exec.CommandContext(ctx, "go", args...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()
	execCmd.Dir = planDir

	log.Info().Str("plan", planPath).Bool("dry-run", dryRun).Msg("executing plan")

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("plan execution failed: %w", err)
	}

	return nil
}

func debugCommand(ctx context.Context, cmd *cli.Command) error {
	planPath := cmd.String("plan")

	// Determine if planPath is a directory or file
	stat, err := os.Stat(planPath)
	if err != nil {
		return fmt.Errorf("%w: %s", errPlanFileNotFound, planPath)
	}

	var (
		planDir string
		args    []string
	)

	if stat.IsDir() {
		planDir = planPath
		args = []string{"run", "."}
	} else {
		planDir = filepath.Dir(planPath)
		args = []string{"run", filepath.Base(planPath)}
	}

	// Set env var to trigger DOT export instead of execution
	if err := os.Setenv("QUARK_DEBUG_GRAPH", "true"); err != nil {
		return fmt.Errorf("failed to set debug env: %w", err)
	}

	// #nosec G204 -- args constructed from validated plan path
	execCmd := exec.CommandContext(ctx, "go", args...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()
	execCmd.Dir = planDir

	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("debug export failed: %w", err)
	}

	return nil
}

var errPasswordMismatch = errors.New("passwords do not match")

func generateKeyPairCommand(_ context.Context, cmd *cli.Command) error {
	output := cmd.String("output")
	privateKeyPath := output + ".key"
	publicKeyPath := output + ".pub"

	// Check if files already exist.
	if _, err := os.Stat(privateKeyPath); err == nil {
		return fmt.Errorf("%w: %s", errFileExists, privateKeyPath)
	}

	if _, err := os.Stat(publicKeyPath); err == nil {
		return fmt.Errorf("%w: %s", errFileExists, publicKeyPath)
	}

	// Prompt for password.
	password, err := readPassword("Enter password for private key: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Confirm password.
	confirm, err := readPassword("Confirm password: ")
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if string(password) != string(confirm) {
		return errPasswordMismatch
	}

	// Generate key pair.
	keyPair := trust.GenerateKeyPair(password)

	// Write private key.
	if err := os.WriteFile(privateKeyPath, keyPair.PrivateKey, filesystem.FilePermissionsPrivate); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key.
	if err := os.WriteFile(publicKeyPath, keyPair.PublicKey, filesystem.FilePermissionsDefault); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	log.Info().
		Str("private_key", privateKeyPath).
		Str("public_key", publicKeyPath).
		Msg("key pair generated successfully")

	return nil
}

// readPassword prompts for a password without echoing input.
func readPassword(prompt string) ([]byte, error) {
	_, _ = os.Stderr.WriteString(prompt)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))

	_, _ = os.Stderr.WriteString("\n")

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return password, nil
}
