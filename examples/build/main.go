// Package main demonstrates building multi-platform container images with Quark.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/build"
	"github.com/farcloser/quark/sdk/platform"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Note: This example requires:
	// 1. A local Dockerfile at ./Dockerfile
	// 2. Registry credentials configured via environment variables
	// 3. Docker buildx configured for multi-platform builds

	// Configure registry for pushing built images
	ghcr := sdk.NewRegistry(sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: os.Getenv("GHCR_USERNAME"),
		Token:    os.Getenv("GHCR_TOKEN"),
	})

	// Define target image
	targetImage := ghcr.NewImage(sdk.ImageOpts{
		Name:    "myorg/myimage",
		Version: "v1.0.0",
	})

	// Create builder with build context
	builder := sdk.NewBuilder(sdk.BuildOpts{
		Context:    ".",
		Dockerfile: "Dockerfile",
	})

	// Define build node (SSH endpoint with Docker)
	node := sdk.NewNode(sdk.NodeOpts{
		Endpoint:    "sshweet",
		Concurrency: 2, // Allow 2 concurrent builds on this node
	})

	// Build multi-platform image
	// The least busy node is selected; if all nodes are at capacity,
	// the build blocks until a slot becomes available.
	builtImage := builder.Build(targetImage, []*sdk.Node{node}, &build.Options{
		Platforms: []*platform.Platform{&platform.AMD64, &platform.ARM64},
	})

	// Optional: Sign the built image
	// For GitHub Actions keyless signing (Fulcio/OIDC):
	//   signer := sdk.NewSigner(sdk.SignerOpts{
	//       OIDCIssuer: "https://token.actions.githubusercontent.com",
	//       OIDCToken:  os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
	//   })
	//   signedImage := builtImage.Sign(signer, nil)
	//   plan.Add(signedImage)
	//
	// For private key signing:
	//   signer := sdk.NewSigner(sdk.SignerOpts{
	//       PrivateKey:  privateKeyPEM,
	//       KeyPassword: []byte(os.Getenv("KEY_PASSWORD")),
	//   })
	//   signedImage := builtImage.Sign(signer, nil)
	//   plan.Add(signedImage)

	// Add built image to plan - dependencies are auto-discovered
	plan.Add(builtImage)

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("build failed", "error", err)
		os.Exit(1)
	}

	slog.Info("build completed successfully")
}
