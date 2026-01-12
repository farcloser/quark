package defaults

import (
	devsecrets "github.com/farcloser/quark/dev/secrets"
	intsecrets "github.com/farcloser/quark/internal/secrets"
)

// SetDefaultsForSecrets registers the default backends (1Password, Vault).
// Called by kit.Initialize() to configure standard secret resolution.
//
// Note: Age backend is NOT registered by default as it requires explicit configuration.
// Use kit.AddSecretsBackend with AgeConfig to configure Age.
func SetDefaultsForSecrets() {
	r := devsecrets.GetResolver()
	r.Register(&intsecrets.OnePasswordBackend{})
	r.Register(&intsecrets.VaultBackend{})
}
