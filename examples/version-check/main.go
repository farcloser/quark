// Package main demonstrates checking for newer versions of container images.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	plan := sdk.NewPlan("version-check-example")

	// Define images to check for updates
	alpineImage := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Build()

	nginxImage := sdk.NewImage("nginx").
		Domain("docker.io").
		Version("1.25").
		Build()

	// Check if newer versions are available
	plan.VersionCheck("alpine-version").Source(alpineImage).Build()
	plan.VersionCheck("nginx-version").Source(nginxImage).Build()

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("version check failed")
	}

	log.Info().Msg("version check completed successfully")
}
