// Package main demonstrates HashiCorp Vault integration for secrets management.
//
// This example shows how to:
// - Retrieve secrets from Vault KV v2 secrets engine
// - Configure Vault via environment variables
// - Override configuration programmatically
// - Handle Vault-specific errors
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/kit"
	"github.com/farcloser/quark/sdk"
)

// Example demonstrates retrieving registry credentials from HashiCorp Vault.
//
// Vault Setup:
//
// 1. Start Vault (dev mode for testing):
//
//	docker run --rm -p 8200:8200 \
//	  -e VAULT_DEV_ROOT_TOKEN_ID=root \
//	  hashicorp/vault:latest
//
// 2. Configure environment:
//
//	export VAULT_ADDR=http://127.0.0.1:8200
//	export VAULT_TOKEN=root
//	# Optional for Vault Enterprise:
//	export VAULT_NAMESPACE=admin
//
// 3. Create secrets (KV v2 is enabled at "secret/" by default):
//
//	vault kv put secret/registries/ghcr \
//	  username="your-github-username" \
//	  token="ghp_your_github_personal_access_token"
//
//	vault kv put secret/registries/dockerhub \
//	  username="your-dockerhub-username" \
//	  token="dckr_pat_your_token"
//
//	vault kv put secret/myapp/database \
//	  host="db.example.com" \
//	  username="app" \
//	  password="secret123" \
//	  port="5432"
//
// URI Format:
//
//	vault://mount/path/to/secret
//
// Examples:
//   - vault://secret/registries/ghcr     - KV v2 at default "secret" mount
//   - vault://secret/myapp/database      - Nested path under "secret" mount
//   - vault://kv/prod/credentials        - Custom mount named "kv"
//
// Environment Variables:
//
//	VAULT_ADDR       - Vault server address (required)
//	VAULT_TOKEN      - Authentication token (required for token auth)
//	VAULT_NAMESPACE  - Vault namespace (optional, Enterprise only)
//	VAULT_CACERT     - CA certificate path for TLS
//	VAULT_CAPATH     - CA certificate directory for TLS
//	VAULT_CLIENT_CERT - Client certificate for mTLS
//	VAULT_CLIENT_KEY  - Client key for mTLS
//	VAULT_SKIP_VERIFY - Skip TLS verification (not recommended)
//
// CI/CD Usage (GitHub Actions):
//
//	jobs:
//	  build:
//	    runs-on: ubuntu-latest
//	    steps:
//	      - uses: actions/checkout@v4
//	      - name: Import Secrets from Vault
//	        uses: hashicorp/vault-action@v2
//	        with:
//	          url: ${{ secrets.VAULT_ADDR }}
//	          token: ${{ secrets.VAULT_TOKEN }}
//	          secrets: |
//	            secret/data/registries/ghcr username | GHCR_USERNAME ;
//	            secret/data/registries/ghcr token | GHCR_TOKEN
//	      - run: ./your-app
//
// Production Authentication:
//
// For production, use one of these auth methods instead of static tokens:
//   - AppRole: Machine-to-machine authentication
//   - Kubernetes: Service account authentication in K8s
//   - AWS IAM: IAM role-based authentication
//   - JWT/OIDC: Identity provider authentication
//
// Note: This example uses token auth. Future versions will support additional
// authentication methods.
func main() {
	ctx := context.Background()

	// Verify Vault is configured
	if os.Getenv("VAULT_ADDR") == "" {
		slog.Error("VAULT_ADDR environment variable not set")
		slog.Info("Set it to your Vault server: export VAULT_ADDR=http://127.0.0.1:8200")
		os.Exit(1)
	}

	if os.Getenv("VAULT_TOKEN") == "" {
		slog.Error("VAULT_TOKEN environment variable not set")
		slog.Info("Set it to your Vault token: export VAULT_TOKEN=root")
		os.Exit(1)
	}

	slog.Info("retrieving registry credentials from Vault",
		"addr", os.Getenv("VAULT_ADDR"))

	// Retrieve credentials from Vault KV v2
	// URI format: vault://mount/path
	credentials, err := kit.GetSecret(
		ctx,
		"vault://secret/registries/ghcr",
		[]string{"username", "token"},
	)
	if err != nil {
		slog.Error("failed to retrieve credentials from Vault", "error", err)
		os.Exit(1)
	}

	username := credentials["username"]
	token := credentials["token"]

	slog.Info("successfully retrieved credentials from Vault", "username", username)

	// Use credentials with Quark SDK
	plan := sdk.NewPlan()

	ghcr := sdk.NewRegistry(sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: username,
		Token:    token,
	})

	slog.Info("registry configured with Vault credentials", "registry", "ghcr.io")

	// Example: Programmatic configuration override
	// Useful when you need different Vault instances per environment
	//
	// backend := secrets.AddVaultBackend(&secrets.VaultBackendConfig{
	//     Address:   "https://vault.prod.example.com:8200",
	//     Token:     os.Getenv("PROD_VAULT_TOKEN"),
	//     Namespace: "production",
	// })
	// resolver := secrets.NewResolver()
	// resolver.Register(backend)

	// Example: Get entire secret as JSON document
	// secretJSON, err := secrets.GetSecretDocument(ctx, "vault://secret/myapp/config")

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

	slog.Info("Vault integration example completed successfully")
}
