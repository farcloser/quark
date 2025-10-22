// Package main demonstrates syncing container images between registries.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	plan := sdk.NewPlan("sync-example")

	// Configure destination registry credentials
	// Note: Replace with your actual registry credentials
	// For docker.io, you can use read-only public access by leaving empty
	plan.Registry("docker.io").
		Username(sdk.GetEnv("DOCKER_USERNAME")).
		Password(sdk.GetEnv("DOCKER_PASSWORD")).
		Build()

	// Define source image to sync
	sourceImage := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Digest("sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0").
		Build()

	// Define destination image
	// Note: Update with your actual registry and credentials
	destImage := sdk.NewImage("myorg/alpine-mirror").
		Domain("docker.io").
		Version("3.19").
		Build()

	// Sync image from source to destination registry
	// Includes both AMD64 and ARM64 platforms
	plan.Sync("example-sync").
		Source(sourceImage).
		Destination(destImage).
		Platforms(sdk.PlatformAMD64, sdk.PlatformARM64).
		Build()

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("sync failed")
	}

	log.Info().Msg("sync completed successfully")
}
