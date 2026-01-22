package dockle

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/internal/types"
	"github.com/farcloser/quark/pkg/dev/tools"
	"github.com/farcloser/quark/pkg/fault"
)

//nolint:gochecknoglobals
var (
	// Dockle container image linter - pinned to v0.4.15 (commit 5436857).
	dockleTool = tools.GoTool{
		Name:       "dockle",
		ImportPath: "github.com/goodwithtech/dockle/cmd/dockle",
		Version:    "5436857", // v0.4.15 released 2025-01-06
	}
)

// Detail represents a single dockle issue detail.
type Detail struct {
	Code   string   `json:"code"`
	Title  string   `json:"title"`
	Level  string   `json:"level"`
	Alerts []string `json:"alerts"`
}

// ScanResult represents dockle scan results.
type ScanResult struct {
	Details []Detail `json:"details"`
}

// Scanner provides auditing for container images.
type Scanner interface {
	ScanImage(ctx context.Context, imageRef string, creds *types.RegistryCredentials) (*ScanResult, error)
}

// NewScanner creates a new Dockle scanner.
func NewScanner(ctx context.Context, log *slog.Logger) (Scanner, error) {
	scanner := &dockleScanner{
		log: log.With("component", "dockle"),
	}

	var err error
	// Ensure dockle is installed
	scanner.docklePath, err = dockleTool.Ensure(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	return scanner, nil
}
