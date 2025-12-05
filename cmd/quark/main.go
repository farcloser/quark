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
	"github.com/farcloser/quark/kit/logger"
	"github.com/farcloser/quark/kit/network"
	"github.com/farcloser/quark/kit/trust"
)

var (
	errPlanFileNotFound = errors.New("plan file not found")
	errFileExists       = errors.New("file already exists")
)

func main() {
	ctx := context.Background()
	// SetDefaults zerolog with LOG_LEVEL env var support
	logger.SetDefaults(ctx)
	// SetDefaults http transport before doing anything else
	network.SetDefaults()

	cmd := &cli.Command{
		Name:    "quark",
		Usage:   "Container image management tool",
		Version: "0.1.0",
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
				},
				Action: executeCommand,
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

func executeCommand(_ context.Context, cmd *cli.Command) error {
	planPath := cmd.String("plan")
	dryRun := cmd.Bool("dry-run")

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

	// #nosec G204 -- args constructed from validated plan path, executing go run is intentional
	execCmd := exec.Command("go", args...)
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
	keyPair, err := trust.GenerateKeyPair(password)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

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
