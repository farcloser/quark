package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/version"
	"github.com/farcloser/quark/sdk/update"
)

type updateAction struct {
	resource.BaseResource[updateAction]

	log   *slog.Logger
	opts  *update.Options
	image *Image
}

func (ua *updateAction) Execute(ctx context.Context) error {
	// If no tag, warn and return without error
	if ua.image.ref.Tag == "" {
		ua.log.WarnContext(ctx, "image has no tag, cannot check for updates",
			slog.String("image", ua.image.ref.String()))

		return nil
	}

	if ua.opts == nil {
		ua.opts = &update.Options{}
	}

	client := registry.NewClient(ua.image.registry.credentials(), ua.log)
	checker := version.NewChecker(client, ua.log)

	// Clear digest to check version by tag
	ua.image.ref.Digest = ""

	info, err := checker.CheckVersion(ctx, *ua.image.ref)
	if err != nil {
		return fmt.Errorf("%w: %w", update.ErrCheckUpdateFailed, err)
	}

	if !info.UpdateAvailable {
		ua.log.DebugContext(ctx, "image is up to date",
			slog.String("image", ua.image.ref.String()),
			slog.String("version", info.CurrentVersion))

		return nil
	}

	// Update available - update the image reference
	ua.log.InfoContext(ctx, "updating image to newer version",
		slog.String("image", ua.image.ref.Name()),
		slog.String("from", info.CurrentVersion),
		slog.String("to", info.LatestVersion))

	ua.image.ref.Tag = info.LatestVersion
	ua.image.ref.ExplicitTag = info.LatestVersion

	return nil
}
