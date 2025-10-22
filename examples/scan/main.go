// Package main demonstrates scanning container images for vulnerabilities.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	plan := sdk.NewPlan("scan-example")

	// Define image to scan - using a public image as example
	// Note: Scan requires a digest for security/reproducibility
	// Get digest with: docker pull alpine:3.19 && docker inspect alpine:3.19 --format='{{index .RepoDigests 0}}'
	exampleImage := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Digest("sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0").
		Build()

	// Scan image for vulnerabilities
	// Fail on critical vulnerabilities, warn on high severity
	plan.Scan("example-scan").
		Source(exampleImage).
		Severity(sdk.SeverityCritical).
		Severity(sdk.SeverityHigh, sdk.ActionWarn).
		Format(sdk.FormatTable).
		Build()

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("scan failed")
	}

	log.Info().Msg("scan completed successfully")
}
