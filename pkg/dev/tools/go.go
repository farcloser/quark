package tools

import (
	"context"
	"path/filepath"
)

// EnsureGo ensures we have a golang toolchain available locally.
func EnsureGo(ctx context.Context) (string, error) {
	goRoot, err := (&HTTPRelease{
		Name:        "go",
		Version:     "1.25.5",
		URLTemplate: "https://go.dev/dl/go%s.%s-%s.tar.gz",
		// PathInArchive empty = extract entire archive
		Checksums: map[string]string{
			"darwin/amd64": "sha256:b69d51bce599e5381a94ce15263ae644ec84667a5ce23d58dc2e63e2c12a9f56",
			"darwin/arm64": "sha256:bed8ebe824e3d3b27e8471d1307f803fc6ab8e1d0eb7a4ae196979bd9b801dd3",
			"linux/amd64":  "sha256:9e9b755d63b36acf30c12a9a3fc379243714c1c6d3dd72861da637f336ebb35b",
			"linux/arm64":  "sha256:b00b694903d126c588c378e72d3545549935d3982635ba3f7a964c9fa23fe3b9",
		},
	}).Ensure(ctx)
	if err != nil {
		return "", err
	}

	return filepath.Join(goRoot, "go", "bin", "go"), nil
}
