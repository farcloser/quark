// Package main demonstrates scanning container images for vulnerabilities.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/logger"
)

func main() {
	ctx := context.Background()
	logger.ConfigureWithDefaults(ctx)

	plan := sdk.NewPlan("scan-example")

	// Define image to scan - using a public image as example
	// Note: Scan requires a digest for security/reproducibility
	// Get digest with: docker pull alpine:3.19 && docker inspect alpine:3.19 --format='{{index .RepoDigests 0}}'
	exampleImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Domain:  "docker.io",
		Version: "3.19",
		Digest:  "sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0",
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create image")
	}

	// Scan image for vulnerabilities
	// Fail on critical vulnerabilities, warn on high severity
	if _, err := plan.Scan(&sdk.ScanArgs{
		Description: "example-scan",
		Source:      exampleImage,
		SeverityChecks: []sdk.ScanSeverityCheck{
			{Threshold: sdk.SeverityCritical, Action: sdk.ActionError},
			{Threshold: sdk.SeverityHigh, Action: sdk.ActionWarn},
		},
		Format: sdk.FormatTable,
	}); err != nil {
		log.Fatal().Err(err).Msg("failed to create scan")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("scan failed")
	}

	log.Info().Msg("scan completed successfully")
}
