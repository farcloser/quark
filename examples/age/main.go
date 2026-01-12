// Package main demonstrates age encryption integration for secrets management.
//
// This example shows how to:
// - Retrieve secrets from age-encrypted JSON files
// - Navigate nested JSON structures within encrypted files
// - Use age encryption for local development and CI/CD
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/kit"
	"github.com/farcloser/quark/sdk"
)

// Example demonstrates retrieving registry credentials from an age-encrypted file.
//
// Age Encryption Setup:
//
// 1. Generate an age identity (private key):
//
//	age-keygen -o ~/.config/quark/identity.txt
//
// 2. Create a secrets JSON file:
//
//	cat > secrets.json << 'EOF'
//	{
//	  "registries": {
//	    "ghcr": {
//	      "username": "your-github-username",
//	      "token": "ghp_your_github_personal_access_token"
//	    },
//	    "dockerhub": {
//	      "username": "your-dockerhub-username",
//	      "token": "dckr_pat_your_token"
//	    }
//	  },
//	  "api_keys": {
//	    "sentry_dsn": "https://xxx@sentry.io/123"
//	  }
//	}
//	EOF
//
// 3. Encrypt the file with your age public key:
//
//	age -r age1... -o secrets.json.age secrets.json
//	rm secrets.json  # Remove plaintext file
//
// 4. Set environment variable pointing to your identity:
//
//	export HADRON_AGE_IDENTITY=~/.config/quark/identity.txt
//
// URI Format:
//
//	age://path/to/file.age[/json/path]
//
// Examples:
//   - age://secrets.json.age                     - Root of decrypted JSON
//   - age://secrets.json.age/registries/ghcr    - Navigate to nested object
//   - age://config/prod.json.age/database       - Relative path with JSON navigation
//
// CI/CD Usage:
//
// Store the age identity as a secret in your CI system:
//
//	# GitHub Actions
//	jobs:
//	  build:
//	    runs-on: ubuntu-latest
//	    steps:
//	      - uses: actions/checkout@v4
//	      - name: Setup age identity
//	        run: |
//	          mkdir -p ~/.config/quark
//	          echo "${{ secrets.AGE_IDENTITY }}" > ~/.config/quark/identity.txt
//	          chmod 600 ~/.config/quark/identity.txt
//	        env:
//	          HADRON_AGE_IDENTITY: ~/.config/quark/identity.txt
//	      - run: ./your-app
func main() {
	ctx := context.Background()

	// Verify identity is configured
	if os.Getenv("HADRON_AGE_IDENTITY") == "" {
		slog.Error("HADRON_AGE_IDENTITY environment variable not set")
		slog.Info(
			"Set it to the path of your age identity file: export HADRON_AGE_IDENTITY=~/.config/quark/identity.txt",
		)
		os.Exit(1)
	}

	slog.Info("retrieving registry credentials from age-encrypted file")

	// Retrieve credentials from age-encrypted JSON file
	// The path navigates into the JSON structure: secrets.json.age -> registries -> ghcr
	credentials, err := kit.GetSecret(
		ctx,
		"age://secrets.json.age/registries/ghcr",
		[]string{"username", "token"},
	)
	if err != nil {
		slog.Error("failed to retrieve credentials", "error", err)
		os.Exit(1)
	}

	username := credentials["username"]
	token := credentials["token"]

	slog.Info("successfully retrieved credentials from age-encrypted file", "username", username)

	// Use credentials with Quark SDK
	plan := sdk.NewPlan()

	ghcr := sdk.NewRegistry(sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: username,
		Token:    token,
	})

	slog.Info("registry configured with age-encrypted credentials", "registry", "ghcr.io")

	// Example: retrieve raw document content (e.g., SSH key, certificate)
	// sshKey, err := secrets.GetSecretDocument(ctx, "age://keys/deploy-key.age")

	// Example usage with image operations
	image := ghcr.NewImage(sdk.ImageOpts{
		Name:    "my-org/my-app",
		Version: "latest",
	})

	plan.Add(image)

	if err := plan.Execute(ctx); err != nil {
		slog.Error("plan execution failed", "error", err)
		os.Exit(1)
	}

	slog.Info("age encryption example completed successfully")
}
