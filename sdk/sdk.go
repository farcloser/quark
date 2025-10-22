// Package sdk provides the public API for Quark container image management.
package sdk

// GetSecret retrieves multiple fields from a 1Password item in a single call.
// Reference format: "op://vault/item"
//
// Example usage in plans:
//
//	secrets, err := sdk.GetSecret(ctx, "op://Security (build)/deploy.registry.rw",
//	    []string{"organization", "username", "password", "domain"})
//	if err != nil {
//	    log.Fatal().Err(err).Msg("failed to retrieve registry credentials")
//	}
//	registryOrg := secrets["organization"]
//	registryUser := secrets["username"]
//	registryPass := secrets["password"]
//	registryDomain := secrets["domain"]
//
// Retrieves the entire item once and extracts the requested fields efficiently.
//
// Requires OP_SERVICE_ACCOUNT_TOKEN environment variable to be set.
// Wraps Hadron's GetSecret for convenience.
//
