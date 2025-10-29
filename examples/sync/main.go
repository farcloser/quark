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
	username, err := sdk.GetEnv("DOCKER_USERNAME")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get DOCKER_USERNAME")
	}

	password, err := sdk.GetEnv("DOCKER_PASSWORD")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get DOCKER_PASSWORD")
	}

	plan.Registry("docker.io").
		Username(username).
		Password(password).
		Build()

	// Define source image to sync
	sourceImage, err := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Digest("sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0").
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create source image")
	}

	// Define destination image
	// Note: Update with your actual registry and credentials
	destImage, err := sdk.NewImage("myorg/alpine-mirror").
		Domain("docker.io").
		Version("3.19").
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create destination image")
	}

	// Sync image from source to destination registry
	// Includes both AMD64 and ARM64 platforms
	if _, err := plan.Sync("example-sync").
		Source(sourceImage).
		Destination(destImage).
		Platforms(sdk.PlatformAMD64, sdk.PlatformARM64).
		Build(); err != nil {
		log.Fatal().Err(err).Msg("failed to create sync")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("sync failed")
	}

	log.Info().Msg("sync completed successfully")
}
