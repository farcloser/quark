// Package main demonstrates building multi-platform container images with Quark.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	plan := sdk.NewPlan("build-example")

	// Note: This example requires:
	// 1. A local Dockerfile at ./Dockerfile
	// 2. Registry credentials configured
	// 3. Docker buildx configured for multi-platform builds
	//
	// Configure registry for pushing built images
	// Replace with your actual registry credentials
	// plan.Registry("ghcr.io").
	//	Username(sdk.GetEnv("REGISTRY_USERNAME")).
	//	Password(sdk.GetEnv("REGISTRY_PASSWORD")).
	//	Build()

	// Define local buildkit nodes for multi-platform builds
	amd64Builder, err := plan.BuildNode("amd64-builder").
		Endpoint("localhost").
		Platform(sdk.PlatformAMD64).
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create amd64 build node")
	}

	arm64Builder, err := plan.BuildNode("arm64-builder").
		Endpoint("localhost").
		Platform(sdk.PlatformARM64).
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create arm64 build node")
	}

	// Build multi-platform image using local docker buildx
	// Replace with your actual image tag
	if _, err := plan.Build("example-build").
		Context(".").
		Dockerfile("Dockerfile").
		Node(amd64Builder).
		Node(arm64Builder).
		Tag("ghcr.io/myorg/myimage:latest").
		Build(); err != nil {
		log.Fatal().Err(err).Msg("failed to create build")
	}

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("build failed")
	}

	log.Info().Msg("build completed successfully")
}
