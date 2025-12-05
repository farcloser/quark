// Package main demonstrates syncing container images between registries.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/kit/env"
	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/sync"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure destination registry credentials
	// Note: Replace with your actual registry credentials
	username, err := env.Get("DOCKER_USERNAME")
	if err != nil {
		slog.Error("failed to get DOCKER_USERNAME", "error", err)
		os.Exit(1)
	}

	password, err := env.Get("DOCKER_PASSWORD")
	if err != nil {
		slog.Error("failed to get DOCKER_PASSWORD", "error", err)
		os.Exit(1)
	}

	// Configure Docker Hub registry with credentials for pushing
	dockerHub := sdk.NewRegistry(sdk.RegistryOpts{
		Domain:   "docker.io",
		Username: username,
		Token:    password,
	})

	// Define source image to sync
	sourceImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.19",
		Digest:  "sha256:6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0",
	})

	// Define destination image
	// Note: Update with your actual registry and credentials
	destImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "myorg/alpine-mirror",
		Version: "3.19",
	})

	// Sync image from source to destination registry
	// Includes both AMD64 and ARM64 platforms
	syncedImage := sourceImage.SyncTo(destImage, &sync.Options{
		Platforms: []platform.Platform{platform.AMD64, platform.ARM64},
	})

	// Add synced image to plan - dependencies are auto-discovered
	plan.Add(syncedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("sync failed", "error", err)
		os.Exit(1)
	}

	slog.Info("sync completed successfully")
}
