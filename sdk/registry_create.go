package sdk

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/types"
)

// createRegistryAction initializes a registry by performing authentication check.
type createRegistryAction struct {
	*resource.BaseAction

	output *Registry
}

func (a *createRegistryAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
}

// Execute performs preflight authentication check and docker login against the registry.
func (a *createRegistryAction) Execute(ctx context.Context) error {
	logger := a.output.log
	reg := a.output.options

	logger.DebugContext(ctx, "authenticating registry")

	client := registry.NewClient(&types.RegistryCredentials{
		Domain:   reg.Domain,
		Username: reg.Username,
		Password: reg.Token,
	}, logger.With("internal", "registry"))

	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRegistryAuth, reg.Domain, err)
	}

	// Perform docker login if credentials are available
	if reg.Username != "" {
		if err := dockerLogin(ctx, reg.Domain, reg.Username, reg.Token); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrRegistryAuth, reg.Domain, err)
		}

		logger.InfoContext(ctx, "docker login successful", "registry", reg.Domain)
	}

	logger.DebugContext(ctx, "registry creation executed")

	return nil
}

// dockerLogin performs docker login to a registry.
func dockerLogin(ctx context.Context, registry, username, password string) error {
	cmd := exec.CommandContext(ctx, "docker", "login", "-u", username, "--password-stdin", registry)
	cmd.Stdin = strings.NewReader(password)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w (output: %s)", ErrDockerLogin, err, string(output))
	}

	return nil
}
