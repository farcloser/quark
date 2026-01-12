// Package main demonstrates checking for newer versions of container images.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure Docker Hub registry (public access, no credentials needed for pulls)
	dockerHub := sdk.NewRegistry(sdk.RegistryOpts{
		Domain: "docker.io",
	})

	// Define images to check for updates
	alpineImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.19",
	})

	nginxImage := dockerHub.NewImage(sdk.ImageOpts{
		Name:    "nginx",
		Version: "1.25",
	})

	// Check if newer versions are available
	// Update() returns a new image representing the post-update state
	updatedAlpine := alpineImage.Update(nil)
	updatedNginx := nginxImage.Update(nil)

	// Add updated images to plan - dependencies are auto-discovered
	plan.Add(updatedAlpine, updatedNginx)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("version check failed", "error", err)
		os.Exit(1)
	}

	slog.Info("version check completed successfully")
}
