// Package main demonstrates building multi-platform container images with Quark.
//
// This example shows how to:
// - Lint Dockerfiles before building
// - Build multi-platform images using remote BuildKit nodes
// - Configure build options (platforms, build args)
// - Sign built images (optional)
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	"github.com/farcloser/quark/sdk/build"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/policy"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Note: This example requires:
	// 1. A local Dockerfile at ./Dockerfile
	// 2. Registry credentials configured via environment variables
	// 3. SSH access to a BuildKit-enabled node

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
	builder := sdk.NewBuilder(sdk.BuilderOpts{
		Context:    ".",
		Dockerfile: "Dockerfile",
	})

	// ============================================
	// LINT: Validate Dockerfile before building
	// ============================================
	//
	// Linting catches common Dockerfile issues:
	// - Missing version pins (DL3006, DL3007)
	// - Shell script issues via ShellCheck
	// - Security issues (running as root, etc.)
	// - Best practice violations
	//
	// The lint action only collects results. Use:
	// - Check() with a policy for enforcement decisions
	// - Log() for formatted output

	// Lint the Dockerfile
	lintedBuilder := builder.Lint()

	// Check: Enforce no lint errors (strict)
	checkedBuilder := lintedBuilder.Check(
		policy.Lint{Error: 0, Warning: policy.Ignore, Info: policy.Ignore, Style: policy.Ignore},
	)

	// Alternative: Allow some issues with limits
	// checkedBuilder := lintedBuilder.Check(policy.Lint{Error: 0, Warning: 5}) // 0 errors, 5 warnings max

	// Alternative: Custom policy
	// checkedBuilder := lintedBuilder.Check(policy.BuilderFunc("custom-lint-policy",
	//     func(ctx context.Context, input *policy.BuilderInput) policy.Result {
	//         if input.Lint != nil && input.Lint.Error > 0 {
	//             return policy.Result{Verdict: policy.Deny, Message: "lint errors found"}
	//         }
	//         return policy.Result{Verdict: policy.Allow, Message: "lint ok"}
	//     },
	// ))

	// Log: Output lint results at appropriate log levels
	loggedBuilder := checkedBuilder.Log(&sdklog.Options{
		LintLevels: sdklog.LintLevelsDefault,
		// Alternative: LintLevelsStrict logs errors and warnings at error level
		// Alternative: LintLevelsQuiet only logs errors
	})

	// Define build node (SSH endpoint with Docker/BuildKit)
	node := sdk.NewNode(sdk.NodeOpts{
		Endpoint:    "sshweet",
		Concurrency: 2, // Allow 2 concurrent builds on this node
	})

	// Build multi-platform image using the linted builder
	// The least busy node is selected; if all nodes are at capacity,
	// the build blocks until a slot becomes available.
	builtImage := loggedBuilder.Build(targetImage, []*sdk.Node{node}, &build.Options{
		Platforms: []*platform.Platform{platform.AMD64, platform.ARM64},
		// Build arguments:
		// Args: map[string]string{
		//     "VERSION": "1.0.0",
		//     "BUILD_DATE": time.Now().Format(time.RFC3339),
		// },
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
