// Package main demonstrates auditing Dockerfiles and container images.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/audit"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/policy"
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
		Digest:  "sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0",
	})

	// Audit image, ignoring specific checks
	auditedImage := exampleImage.Audit(&audit.Options{
		Ignore: []string{"CIS-DI-0001"},
	})

	// Apply policy: fail on any fatal issues, allow up to 5 warnings
	checkedImage := auditedImage.Check(
		policy.Audit{Fatal: 0, Warn: 5, Info: policy.Ignore},
	)

	// Log results with severity-based log levels
	loggedImage := checkedImage.Log(&sdklog.Options{
		Format:      sdklog.FormatTable,
		AuditLevels: sdklog.AuditLevelsDefault,
	})

	// Add logged image to plan - dependencies are auto-discovered
	plan.Add(loggedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("audit failed", "error", err)
		os.Exit(1)
	}

	slog.Info("audit completed successfully")
}
