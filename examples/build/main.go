// Package main demonstrates building multi-platform container images with Quark.
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

	plan := sdk.NewPlan("build-example")

	// Note: This example requires:
	// 1. A local Dockerfile at ./Dockerfile
	// 2. Registry credentials configured
	// 3. Docker buildx configured for multi-platform builds
	//
	// Configure registry for pushing built images
	// Replace with your actual registry credentials
	// plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
	//     Domain:   "ghcr.io",
	//     Username: username,
	//     Token:    password,
	// }))

	// Define local buildkit nodes for multi-platform builds
	amd64Builder, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "amd64-builder",
		Endpoint: "localhost",
		Platform: sdk.PlatformAMD64,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create amd64 build node")
	}

	plan.AddBuildNode(amd64Builder)

	arm64Builder, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "arm64-builder",
		Endpoint: "localhost",
		Platform: sdk.PlatformARM64,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create arm64 build node")
	}

	plan.AddBuildNode(arm64Builder)

	// Build multi-platform image using local docker buildx
	// Replace with your actual image tag
	if _, err := plan.Build(&sdk.BuildArgs{
		Name:       "example-build",
		Context:    ".",
		Dockerfile: "Dockerfile",
		Nodes:      []*sdk.BuildNode{amd64Builder, arm64Builder},
		Tag:        "ghcr.io/myorg/myimage:latest",
	}); err != nil {
		log.Fatal().Err(err).Msg("failed to create build")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("build failed")
	}

	log.Info().Msg("build completed successfully")
}
