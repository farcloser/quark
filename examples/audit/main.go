// Package main demonstrates auditing Dockerfiles and container images.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/audit"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure Docker Hub registry (public access)
	dockerHub := sdk.NewRegistry(sdk.RegistryOpts{
		Domain: "docker.io",
	})

	// Define image to audit
	exampleImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.19",
	})

	// Audit image against strict ruleset
	// Note: Dockerfile audit requires local Dockerfile path
	auditedImage := exampleImage.Audit(&audit.Options{
		SeverityChecks: audit.SetSeverityCheckStrict,
		Ignore:         []string{"CIS-DI-0001"},
	})

	// Add audited image to plan - dependencies are auto-discovered
	plan.Add(auditedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("audit failed", "error", err)
		os.Exit(1)
	}

	slog.Info("audit completed successfully")
}
