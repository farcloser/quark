// Package main demonstrates syncing container images between registries.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/env"
	"github.com/farcloser/quark/sdk/logger"
)

func main() {
	ctx := context.Background()
	logger.ConfigureWithDefaults(ctx)

	plan := sdk.NewPlan("sync-example")

	// Configure destination registry credentials
	// Note: Replace with your actual registry credentials
	// For docker.io, you can use read-only public access by leaving empty
	username, err := env.Get("DOCKER_USERNAME")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get DOCKER_USERNAME")
	}

	password, err := env.Get("DOCKER_PASSWORD")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get DOCKER_PASSWORD")
	}

	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "docker.io",
		Username: username,
		Token:    password,
	}))

	// Define source image to sync
	sourceImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Domain:  "docker.io",
		Version: "3.19",
		Digest:  "sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0",
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create source image")
	}

	// Define destination image
	// Note: Update with your actual registry and credentials
	destImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myorg/alpine-mirror",
		Domain:  "docker.io",
		Version: "3.19",
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create destination image")
	}

	// Sync image from source to destination registry
	// Includes both AMD64 and ARM64 platforms
	if _, err := plan.Sync(&sdk.SyncArgs{
		Description: "example-sync",
		Source:      sourceImage,
		Destination: destImage,
		Platforms:   []sdk.Platform{sdk.PlatformAMD64, sdk.PlatformARM64},
	}); err != nil {
		log.Fatal().Err(err).Msg("failed to create sync")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("sync failed")
	}

	log.Info().Msg("sync completed successfully")
}
