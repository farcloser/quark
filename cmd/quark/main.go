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

	"github.com/farcloser/quark/sdk"
)

var errPlanFileNotFound = errors.New("plan file not found")

func main() {
	ctx := context.Background()
	// Configure zerolog with LOG_LEVEL env var support
	sdk.ConfigureDefaultLogger(ctx)

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
