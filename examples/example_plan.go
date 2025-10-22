// Package main documents examples for Quark SDK
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)
	_ = sdk.LoadEnv("./.env")

	plan := sdk.NewPlan("example-pipeline")

	// Define images with domain
	vectorImage := sdk.NewImage("timberio/vector").
		Domain("docker.io").
		Version(sdk.GetEnv("VECTOR_VERSION")).
		Digest(sdk.GetEnv("VECTOR_DIGEST")).
		Build()

	// Caddy without digest - will show warning
	caddyImage := sdk.NewImage("caddy").
		Domain("docker.io").
		Version(sdk.GetEnv("CADDY_VERSION")).
		Build()

	// Check for version updates
	plan.VersionCheck("vector-version").Source(vectorImage).Build()
	plan.VersionCheck("caddy-version").Source(caddyImage).Build()

	// Retrieve registry credentials from 1Password
	ghcrSecrets, err := sdk.GetSecret(ctx, "op://Security (build)/deploy.registry.rw",
		[]string{"username", "password"})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to retrieve GHCR credentials from 1Password")
	}

	ghcrUsername := ghcrSecrets["username"]
	ghcrToken := ghcrSecrets["password"]

	dockerhubSecrets, err := sdk.GetSecret(ctx, "op://Security (build)/deploy.docker.io.ro",
		[]string{"username", "password"})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to retrieve Docker Hub credentials from 1Password")
	}

	dockerhubUsername := dockerhubSecrets["username"]
	dockerhubPassword := dockerhubSecrets["password"]

	// Configure registries (stored in plan's registry collection)
	plan.Registry("ghcr.io").
		Username(ghcrUsername).
		Password(ghcrToken).
		Build()

	plan.Registry("docker.io").
		Username(dockerhubUsername).
		Password(dockerhubPassword).
		Build()

	// Define buildkit nodes - using local docker buildx
	// Omit Endpoint() to use local docker buildx instead of SSH
	amd64Builder := plan.BuildNode("amd64-builder").
		Platform(sdk.PlatformAMD64).
		Build()

	arm64Builder := plan.BuildNode("arm64-builder").
		Platform(sdk.PlatformARM64).
		Build()

	// Build multi-platform image
	plan.Build("example-build").
		Context("./docker/example").
		Dockerfile("Dockerfile").
		Node(amd64Builder).
		Node(arm64Builder).
		Tag(sdk.GetEnv("EXAMPLE_IMAGE_TAG")).
		Build()

	// Define example image for syncing
	exampleImage := sdk.NewImage(sdk.GetEnv("EXAMPLE_IMAGE_TAG")).
		Digest(sdk.GetEnv("EXAMPLE_IMAGE_DIGEST")).
		Build()

	// Audit Dockerfile and image
	plan.Audit("example-audit").
		Dockerfile("./docker/example/Dockerfile").
		Source(exampleImage).
		RuleSet(sdk.RuleSetStrict).
		Build()

	exampleDest := sdk.NewImage("myorg/example").
		Version("latest").
		Build()

	exampleDestImage := plan.Sync("example-sync").
		Source(exampleImage).
		Destination(exampleDest).
		Platforms(sdk.PlatformAMD64, sdk.PlatformARM64).
		Build()

	// Scan destination image after sync (digest auto-populated during plan execution)
	_ = plan.Scan("example-scan").
		Source(exampleDestImage).
		Severity(sdk.SeverityCritical).
		Severity(sdk.SeverityHigh, sdk.ActionWarn).
		Format(sdk.FormatTable).
		Build()

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("Plan execution failed")
	}
}
