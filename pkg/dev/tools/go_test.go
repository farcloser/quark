package tools_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/farcloser/quark/pkg/dev/tools"
)

// INTENTION: EnsureGo should download, install, and return a working Go binary.
func TestEnsureGo_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	goPath, err := tools.EnsureGo(ctx)
	if err != nil {
		t.Fatalf("EnsureGo failed: %v", err)
	}

	// Verify binary exists
	info, err := os.Stat(goPath)
	if err != nil {
		t.Fatalf("binary not found at %s: %v", goPath, err)
	}

	if info.Mode()&0o111 == 0 {
		t.Errorf("binary is not executable: mode=%v", info.Mode())
	}

	// Verify it runs and reports correct version
	cmd := exec.CommandContext(ctx, goPath, "version")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go version failed: %v\npath: %s\noutput: %s", err, goPath, output)
	}

	if !strings.Contains(string(output), "go1.25.5") {
		t.Errorf("unexpected version output: %s", output)
	}

	// Verify idempotency - second call should return same path without re-downloading
	goPath2, err := tools.EnsureGo(ctx)
	if err != nil {
		t.Fatalf("second EnsureGo failed: %v", err)
	}

	if goPath2 != goPath {
		t.Errorf("EnsureGo not idempotent: first=%q, second=%q", goPath, goPath2)
	}
}
