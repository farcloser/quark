package buildctl

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/farcloser/quark/dev/fault"
	tools2 "github.com/farcloser/quark/dev/tools"
)

// buildctlRelease defines the buildctl GitHub release configuration.
//
//nolint:gochecknoglobals
var buildctlRelease = tools2.GithubRelease{
	Name:    "buildctl",
	Version: "v0.26.2",
	// URL format: https://github.com/moby/buildkit/releases/download/v0.26.2/buildkit-v0.26.2.darwin-arm64.tar.gz
	URLTemplate: "https://github.com/moby/buildkit/releases/download/%s/buildkit-%s.%s-%s.tar.gz",
	URLArgs: func(version, goos, goarch string) []any {
		return []any{version, version, goos, goarch}
	},
	BinaryPathInArchive: "bin/buildctl",
	Checksums: map[string]string{
		"darwin/amd64": "16728420213cb44070020f19165a1d1bc06f48e3e18149d5d6f7fee177f6c63f",
		"darwin/arm64": "953ef5239e7404ee7d88430f8801e18127bb1fe38e29c3c2d45b1cf9b7460e69",
		"linux/amd64":  "1ef7c888f808e7f3f49d9aeeca11f661afe5c0880a4b114cc31c56dee86acd35",
		"linux/arm64":  "9911bf7081398155ca67edbf9620702b815ba9d8b8c58b4f860f5ed01602bb6d",
	},
}

// installer holds the package-level installer instance.
//
//nolint:gochecknoglobals
var (
	installer     tools2.Installer
	installerOnce sync.Once
)

// EnsureBuildctl ensures buildctl is installed and returns the path to the binary.
func EnsureBuildctl(ctx context.Context, log *slog.Logger) (string, error) {
	installerOnce.Do(func() {
		installer = tools2.NewGithubInstaller(log, buildctlRelease)
	})

	path, err := installer.Ensure(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	return path, nil
}
