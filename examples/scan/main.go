// Package main demonstrates scanning container images for vulnerabilities.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/scan"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure Docker Hub registry (public access)
	dockerHub := sdk.NewRegistry(sdk.RegistryOpts{
		Domain: "docker.io",
	})

	// Define image to scan - using a public image as example
	// Note: Scan requires a digest for security/reproducibility
	// Get digest with: docker pull alpine:3.19 && docker inspect alpine:3.19 --format='{{index .RepoDigests 0}}'
	exampleImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.19",
		Digest:  "sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0",
	})

	// Scan image for vulnerabilities
	// Fail on critical vulnerabilities, warn on high severity
	scannedImage := exampleImage.Scan(&scan.Options{
		SeverityChecks: []scan.SeverityCheck{
			{
				Severities: []*scan.Severity{scan.SeverityCritical},
				Action:     scan.ActionError,
			},
			{
				Severities: []*scan.Severity{scan.SeverityHigh},
				Action:     scan.ActionWarn,
			},
		},
		Format: scan.FormatTable,
	})

	// Add scanned image to plan - dependencies are auto-discovered
	plan.Add(scannedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("scan failed", "error", err)
		os.Exit(1)
	}

	slog.Info("scan completed successfully")
}
