// Package main demonstrates scanning container images for vulnerabilities.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/policy"
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
	scannedImage := exampleImage.Scan(&scan.Options{})

	// Apply policy: fail on critical vulnerabilities, allow up to 10 high
	checkedImage := scannedImage.Check(
		policy.Scan{
			Critical: 0,
			High:     10,
			Medium:   policy.Ignore,
			Low:      policy.Ignore,
			Unknown:  policy.Ignore,
		},
	)

	// Log results with severity-based log levels
	loggedImage := checkedImage.Log(&sdklog.Options{
		Format:     sdklog.FormatTable,
		ScanLevels: sdklog.ScanLevelsDefault,
	})

	// Add logged image to plan - dependencies are auto-discovered
	plan.Add(loggedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("scan failed", "error", err)
		os.Exit(1)
	}

	slog.Info("scan completed successfully")
}
