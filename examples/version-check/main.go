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
	alpineImage, err := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create alpine image")
	}

	nginxImage, err := sdk.NewImage("nginx").
		Domain("docker.io").
		Version("1.25").
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create nginx image")
	}

	// Check if newer versions are available
	if _, err := plan.VersionCheck("alpine-version").Source(alpineImage).Build(); err != nil {
		log.Fatal().Err(err).Msg("failed to create alpine version check")
	}

	if _, err := plan.VersionCheck("nginx-version").Source(nginxImage).Build(); err != nil {
		log.Fatal().Err(err).Msg("failed to create nginx version check")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("version check failed")
	}

	log.Info().Msg("version check completed successfully")
}
