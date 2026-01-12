package layers

import (
	"path/filepath"
	"strings"
)

// Unnecessary files that shouldn't be in production images.
//
//nolint:gochecknoglobals // Read-only configuration.
var deletableFiles = map[string]struct{}{
	"Dockerfile":          {},
	"docker-compose.yml":  {},
	"docker-compose.yaml": {},
	".dockerignore":       {},
	".vimrc":              {},
	".DS_Store":           {},
}

// Unnecessary directories that shouldn't be in production images.
//
//nolint:gochecknoglobals // Read-only configuration.
var deletableDirs = map[string]struct{}{
	".cache":  {},
	".aws":    {},
	".azure":  {},
	".gcp":    {},
	".git":    {},
	".vscode": {},
	".idea":   {},
	".npm":    {},
}

// Directories to skip (dependency directories that may legitimately contain flagged patterns).
//
//nolint:gochecknoglobals // Read-only configuration.
var ignoreDirs = map[string]struct{}{
	"node_modules": {},
	"vendor":       {},
}

type deletableChecker struct {
	seenDirs map[string]struct{} // Track directories already reported to avoid duplicates.
}

func newDeletableChecker() *deletableChecker {
	return &deletableChecker{
		seenDirs: make(map[string]struct{}),
	}
}

func (c *deletableChecker) check(entry FileEntry) *Assessment {
	// Check if path is inside an ignored directory.
	if c.inIgnoreDir(entry.Path) {
		return nil
	}

	// Check for deletable files by basename.
	baseName := filepath.Base(entry.Path)
	if _, isDeletable := deletableFiles[baseName]; isDeletable {
		return &Assessment{
			Code:     CodeInfoDeletableFiles,
			Title:    Titles[CodeInfoDeletableFiles],
			Level:    DefaultLevels[CodeInfoDeletableFiles],
			Message:  "unnecessary file found: " + entry.Path,
			Filename: entry.Path,
		}
	}

	// Check for deletable directories.
	// We check each path component to catch nested occurrences.
	for component := range strings.SplitSeq(entry.Path, "/") {
		if _, isDeletable := deletableDirs[component]; isDeletable {
			// Build the directory path up to this component.
			dirPath := c.findDirPath(entry.Path, component)

			// Only report each directory once.
			if _, seen := c.seenDirs[dirPath]; seen {
				return nil
			}

			c.seenDirs[dirPath] = struct{}{}

			return &Assessment{
				Code:     CodeInfoDeletableFiles,
				Title:    Titles[CodeInfoDeletableFiles],
				Level:    DefaultLevels[CodeInfoDeletableFiles],
				Message:  "unnecessary directory found: " + dirPath,
				Filename: dirPath,
			}
		}
	}

	return nil
}

// inIgnoreDir checks if the path is inside an ignored directory.
func (c *deletableChecker) inIgnoreDir(path string) bool {
	for component := range strings.SplitSeq(path, "/") {
		if _, ignore := ignoreDirs[component]; ignore {
			return true
		}
	}

	return false
}

// findDirPath extracts the path up to and including the target component.
func (c *deletableChecker) findDirPath(fullPath, target string) string {
	parts := strings.Split(fullPath, "/")

	for i, part := range parts {
		if part == target {
			return strings.Join(parts[:i+1], "/")
		}
	}

	return target
}

// reset clears the seen directories for a new layer.
func (c *deletableChecker) reset() {
	c.seenDirs = make(map[string]struct{})
}
