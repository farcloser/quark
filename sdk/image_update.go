package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/version"
	"github.com/farcloser/quark/sdk/update"
)

type updateAction struct {
	*resource.BaseAction

	opts   *update.Options
	output *Image
}

func (ua *updateAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ua, ua.BaseAction, name, out, copyFrom...)
}

func (ua *updateAction) Execute(ctx context.Context) error {
	output := ua.output

	// If no tag, warn and return without error
	if output.ref.Tag == "" {
		output.log.WarnContext(ctx, "image has no tag, cannot check for updates",
			slog.String("image", output.ref.String()))

		return nil
	}

	if ua.opts == nil {
		ua.opts = &update.Options{}
	}

	client := registry.NewClient(output.registry.credentials(), output.log)
	checker := version.NewChecker(client, output.log)

	// Clear digest to check version by tag
	output.ref.Digest = ""

	info, err := checker.CheckVersion(ctx, *output.ref)
	if err != nil {
		return fmt.Errorf("%w: %w", update.ErrCheckUpdateFailed, err)
	}

	if !info.UpdateAvailable {
		output.log.DebugContext(ctx, "image is up to date",
			slog.String("image", output.ref.String()),
			slog.String("version", info.CurrentVersion))

		return nil
	}

	// Update available - update the output image reference
	output.log.InfoContext(ctx, "updating image to newer version",
		slog.String("image", output.ref.Name()),
		slog.String("from", info.CurrentVersion),
		slog.String("to", info.LatestVersion))

	output.ref.Tag = info.LatestVersion
	output.ref.ExplicitTag = info.LatestVersion

	return nil
}
