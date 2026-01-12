// Package main demonstrates copying container images between registries.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/kit"
	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/sync"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure destination registry credentials
	// Note: Replace with your actual registry credentials
	username, err := kit.GetEnv("DOCKER_USERNAME")
	if err != nil {
		slog.Error("failed to get DOCKER_USERNAME", "error", err)
		os.Exit(1)
	}

	password, err := kit.GetEnv("DOCKER_PASSWORD")
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

	// Define source image to copy
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

	// Copy image from source to destination registry
	// Includes both AMD64 and ARM64 platforms
	copiedImage := sourceImage.CopyTo(destImage, &sync.Options{
		Platforms: []*platform.Platform{platform.AMD64, platform.ARM64},
	})

	// Add copied image to plan - dependencies are auto-discovered
	plan.Add(copiedImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("copy failed", "error", err)
		os.Exit(1)
	}

	slog.Info("copy completed successfully")
}
