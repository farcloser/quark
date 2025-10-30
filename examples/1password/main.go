// Package main demonstrates 1Password integration for registry authentication.
//
// This example shows how to:
// - Retrieve registry credentials from 1Password
// - Authenticate with container registries using those credentials
// - Handle authentication errors properly
// - Use 1Password in both local development and CI/CD
package main

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

// Example demonstrates retrieving GHCR credentials from 1Password and using them
// to authenticate with a container registry.
//
// 1Password Item Structure:
// The 1Password item should be structured as follows (using 1Password app or CLI):
//
//	Item Type: Login or API Credential
//	Title: ghcr-credentials (or any name you prefer)
//	Vault: Security (or any vault you prefer)
//	Fields:
//	  - username: your-github-username
//	  - password: ghp_your_github_personal_access_token
//
// You can create this item using the 1Password app or CLI:
//
//	# Using 1Password CLI to create the item
//	op item create \
//	  --category=login \
//	  --title="ghcr-credentials" \
//	  --vault="Security" \
//	  username="your-github-username" \
//	  password="ghp_your_token"
//
// Authentication Methods:
//
// LOCAL DEVELOPMENT (Interactive):
//   - Uses 1Password desktop app integration with biometric authentication
//   - Automatically prompts for fingerprint/face recognition when needed
//   - Session is cached after first authentication
//   - Run: op signin (only needed once per session)
//
// CI/CD (Service Account):
//   - Use 1Password Service Account tokens (no interactive prompts)
//   - Create service account: https://developer.1password.com/docs/service-accounts
//   - Set environment variable: export OP_SERVICE_ACCOUNT_TOKEN=ops_your_token
//   - No additional authentication needed - token is automatically used
//
// Example GitHub Actions workflow:
//
//	jobs:
//	  build:
//	    runs-on: ubuntu-24.04
//	    steps:
//	      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
//	      - name: Set up 1Password
//	        env:
//	          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
//	        run: |
//	          # Install 1Password CLI
//	          curl -sS https://downloads.1password.com/linux/tar/stable/x86_64/op.tar.gz | tar xz
//	          sudo mv op /usr/local/bin/
//	          # Run your quark command - token is automatically detected
//	          ./your-app
func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	// OPTIONAL: Pre-authenticate with 1Password to avoid multiple biometric prompts
	// This is useful if you'll make multiple GetSecret calls in parallel
	// In CI/CD with service accounts, this is a no-op (already authenticated via token)
	if err := sdk.AuthenticateOp(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to authenticate with 1Password")
	}

	log.Info().Msg("retrieving registry credentials from 1Password")

	// Retrieve credentials from 1Password
	// Reference format: op://vault/item
	// This retrieves multiple fields in a single API call (efficient)
	credentials, err := sdk.GetSecret(
		ctx,
		"op://Security/ghcr-credentials",
		[]string{"username", "password"},
	)
	// Handle specific 1Password errors
	if err != nil {
		// Check for common error types to provide helpful messages
		switch {
		case errors.Is(err, sdk.ErrItemReferenceInvalidPrefix):
			log.Fatal().Err(err).Msg("invalid 1Password reference format (must start with 'op://')")
		case errors.Is(err, sdk.ErrItemFieldNotFound):
			log.Fatal().
				Err(err).
				Msg("required field not found in 1Password item (ensure 'username' and 'password' fields exist)")
		case errors.Is(err, sdk.ErrItemReferenceEmpty):
			log.Fatal().Err(err).Msg("1Password reference cannot be empty")
		default:
			// Generic error - likely authentication issue or item not found
			log.Fatal().Err(err).
				Str("reference", "op://Security/ghcr-credentials").
				Msg("failed to retrieve credentials from 1Password (check authentication and item exists)")
		}
	}

	username := credentials["username"]
	password := credentials["password"]

	log.Info().
		Str("username", username).
		Msg("successfully retrieved credentials from 1Password")

	// Create a plan and configure registry with 1Password credentials
	plan := sdk.NewPlan("1password-example")

	// Configure GHCR (GitHub Container Registry) with credentials from 1Password
	if _, err := plan.Registry("ghcr.io").
		Username(username).
		Password(password).
		Build(); err != nil {
		log.Fatal().Err(err).Msg("failed to create registry")
	}

	log.Info().
		Str("registry", "ghcr.io").
		Msg("registry configured with 1Password credentials")

	// Example: Create an image reference that will use these credentials
	// This demonstrates that the credentials are working
	image, err := sdk.NewImage("my-org/my-app").
		Domain("ghcr.io").
		Version("latest").
		Build()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create image reference")
	}

	log.Info().
		Str("image", image.Domain()+"/"+image.Name()+":"+image.Version()).
		Msg("created image reference using 1Password-authenticated registry")

	// In a real application, you would now use this plan to perform operations
	// such as sync, scan, build, etc. The registry authentication is already
	// configured and will be used automatically for all operations on ghcr.io.
	//
	// Example operations you could add:
	//
	//   // Version check
	//   plan.VersionCheck("check").Image(image).Build()
	//
	//   // Scan image for vulnerabilities
	//   plan.Scan("scan").Image(image).Build()
	//
	//   // Execute plan
	//   if err := plan.Execute(ctx); err != nil {
	//       log.Fatal().Err(err).Msg("plan execution failed")
	//   }

	log.Info().Msg("1Password integration example completed successfully")
	log.Info().Msg("credentials retrieved and registry configured - ready for operations")
}
