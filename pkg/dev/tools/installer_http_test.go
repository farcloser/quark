//nolint:testpackage
package tools

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/farcloser/quark/pkg/fault"
)

// =============================================================================
// isSubPath tests - Path traversal protection
// =============================================================================

func TestIsSubPath_ValidPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   string
		target string
		want   bool
	}{
		{
			name:   "simple child",
			base:   "/tmp/dest",
			target: "/tmp/dest/file.txt",
			want:   true,
		},
		{
			name:   "nested child",
			base:   "/tmp/dest",
			target: "/tmp/dest/a/b/c/file.txt",
			want:   true,
		},
		{
			name:   "same as base",
			base:   "/tmp/dest",
			target: "/tmp/dest",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isSubPath(tt.base, tt.target); got != tt.want {
				t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.base, tt.target, got, tt.want)
			}
		})
	}
}

func TestIsSubPath_PathTraversalAttempts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   string
		target string
	}{
		{
			name:   "simple parent escape",
			base:   "/tmp/dest",
			target: "/tmp/dest/../etc/passwd",
		},
		{
			name:   "double parent escape",
			base:   "/tmp/dest",
			target: "/tmp/dest/../../etc/passwd",
		},
		{
			name:   "sibling directory",
			base:   "/tmp/dest",
			target: "/tmp/other/file.txt",
		},
		{
			name:   "absolute path escape",
			base:   "/tmp/dest",
			target: "/etc/passwd",
		},
		{
			name:   "hidden dotdot in path",
			base:   "/tmp/dest",
			target: "/tmp/dest/subdir/../../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isSubPath(tt.base, tt.target); got {
				t.Errorf("isSubPath(%q, %q) = true, want false (path traversal should be blocked)",
					tt.base, tt.target)
			}
		})
	}
}

func TestStartsWithDotDot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"..", true},
		{"../", true},
		{"../foo", true},
		{".." + string(filepath.Separator) + "foo", true}, // Platform-specific separator
		{".", false},
		{"./", false},
		{"foo", false},
		{"foo/..", false},
		{"...foo", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			if got := startsWithDotDot(tt.path); got != tt.want {
				t.Errorf("startsWithDotDot(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// =============================================================================
// extractionBudget tests - Decompression bomb protection
// =============================================================================

func TestExtractionBudget_WithinLimit(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(1000)
	src := bytes.NewReader(make([]byte, 500))
	dst := &bytes.Buffer{}

	written, err := budget.limitedCopy(dst, src)
	if err != nil {
		t.Errorf("limitedCopy() error = %v, want nil", err)
	}

	if written != 500 {
		t.Errorf("limitedCopy() written = %d, want 500", written)
	}

	if budget.remaining != 500 {
		t.Errorf("budget.remaining = %d, want 500", budget.remaining)
	}
}

func TestExtractionBudget_ExceedsLimit(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(100)
	src := bytes.NewReader(make([]byte, 200))
	dst := &bytes.Buffer{}

	_, err := budget.limitedCopy(dst, src)
	if err == nil {
		t.Error("limitedCopy() should return error when budget exceeded")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("limitedCopy() error = %v, want fault.ErrInvalidArgument", err)
	}
}

func TestExtractionBudget_MultipleFiles(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(1000)

	// First file: 400 bytes
	src1 := bytes.NewReader(make([]byte, 400))
	dst1 := &bytes.Buffer{}

	_, err := budget.limitedCopy(dst1, src1)
	if err != nil {
		t.Fatalf("first limitedCopy() error = %v", err)
	}

	// Second file: 400 bytes
	src2 := bytes.NewReader(make([]byte, 400))
	dst2 := &bytes.Buffer{}

	_, err = budget.limitedCopy(dst2, src2)
	if err != nil {
		t.Fatalf("second limitedCopy() error = %v", err)
	}

	// Third file: 300 bytes - should exceed remaining budget (200)
	src3 := bytes.NewReader(make([]byte, 300))
	dst3 := &bytes.Buffer{}

	_, err = budget.limitedCopy(dst3, src3)
	if err == nil {
		t.Error("third limitedCopy() should fail - budget exceeded")
	}
}

// =============================================================================
// tar.gz extraction tests
// =============================================================================

func createTestTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}

		if _, err := tarWriter.Write(content); err != nil {
			t.Fatalf("failed to write tar content: %v", err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	if err := gzWriter.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	return buf.Bytes()
}

func createTarGzWithPathTraversal(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Malicious entry with path traversal
	header := &tar.Header{
		Name: "../../../etc/evil",
		Mode: 0o644,
		Size: 4,
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}

	if _, err := tarWriter.Write([]byte("evil")); err != nil {
		t.Fatalf("failed to write tar content: %v", err)
	}

	_ = tarWriter.Close()
	_ = gzWriter.Close()

	return buf.Bytes()
}

func createTarGzWithSymlink(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Symlink entry
	header := &tar.Header{
		Name:     "malicious-link",
		Mode:     0o777,
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}

	// Also add a regular file to ensure extraction continues
	header2 := &tar.Header{
		Name: "regular-file.txt",
		Mode: 0o644,
		Size: 5,
	}

	if err := tarWriter.WriteHeader(header2); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}

	if _, err := tarWriter.Write([]byte("hello")); err != nil {
		t.Fatalf("failed to write tar content: %v", err)
	}

	_ = tarWriter.Close()
	_ = gzWriter.Close()

	return buf.Bytes()
}

func TestExtractAllFromTarGz_Normal(t *testing.T) {
	t.Parallel()

	data := createTestTarGz(t, map[string][]byte{
		"file1.txt":     []byte("content1"),
		"dir/file2.txt": []byte("content2"),
	})

	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromTarGz(data, destDir)
	if err != nil {
		t.Fatalf("extractAllFromTarGz() error = %v", err)
	}

	// Verify files were extracted
	content1, err := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	if err != nil {
		t.Errorf("failed to read file1.txt: %v", err)
	} else if string(content1) != "content1" {
		t.Errorf("file1.txt content = %q, want %q", content1, "content1")
	}

	content2, err := os.ReadFile(filepath.Join(destDir, "dir/file2.txt"))
	if err != nil {
		t.Errorf("failed to read dir/file2.txt: %v", err)
	} else if string(content2) != "content2" {
		t.Errorf("dir/file2.txt content = %q, want %q", content2, "content2")
	}
}

func TestExtractAllFromTarGz_PathTraversal(t *testing.T) {
	t.Parallel()

	data := createTarGzWithPathTraversal(t)
	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromTarGz(data, destDir)
	if err == nil {
		t.Fatal("extractAllFromTarGz() should fail on path traversal attempt")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want fault.ErrInvalidArgument", err)
	}

	// Verify no file was created outside destDir
	if _, err := os.Stat(filepath.Join(destDir, "../../../etc/evil")); err == nil {
		t.Error("path traversal was not blocked - file exists outside destDir")
	}
}

func TestExtractAllFromTarGz_SymlinkSkipped(t *testing.T) {
	t.Parallel()

	data := createTarGzWithSymlink(t)
	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromTarGz(data, destDir)
	if err != nil {
		t.Fatalf("extractAllFromTarGz() error = %v", err)
	}

	// Verify symlink was NOT created
	if _, err := os.Lstat(filepath.Join(destDir, "malicious-link")); err == nil {
		t.Error("symlink should have been skipped")
	}

	// Verify regular file WAS created
	if _, err := os.Stat(filepath.Join(destDir, "regular-file.txt")); err != nil {
		t.Error("regular file should have been extracted")
	}
}

func TestExtractAllFromTarGz_FilePermissions(t *testing.T) {
	t.Parallel()

	// Create tarball with executable file
	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	header := &tar.Header{
		Name: "executable",
		Mode: 0o755, // Executable
		Size: 4,
	}
	_ = tarWriter.WriteHeader(header)
	_, _ = tarWriter.Write([]byte("exec"))

	header2 := &tar.Header{
		Name: "regular",
		Mode: 0o644, // Not executable
		Size: 4,
	}
	_ = tarWriter.WriteHeader(header2)
	_, _ = tarWriter.Write([]byte("data"))

	_ = tarWriter.Close()
	_ = gzWriter.Close()

	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromTarGz(buf.Bytes(), destDir)
	if err != nil {
		t.Fatalf("extractAllFromTarGz() error = %v", err)
	}

	// Check executable file has execute permission
	execInfo, err := os.Stat(filepath.Join(destDir, "executable"))
	if err != nil {
		t.Fatalf("failed to stat executable: %v", err)
	}

	if execInfo.Mode()&0o100 == 0 {
		t.Error("executable should have execute permission")
	}

	// Check non-executable file does NOT have execute permission
	regInfo, err := os.Stat(filepath.Join(destDir, "regular"))
	if err != nil {
		t.Fatalf("failed to stat regular: %v", err)
	}

	if regInfo.Mode()&0o100 != 0 {
		t.Error("regular file should NOT have execute permission")
	}

	// Verify no group/world permissions (private)
	if execInfo.Mode()&0o077 != 0 {
		t.Errorf("executable has group/world permissions: %o", execInfo.Mode())
	}

	if regInfo.Mode()&0o077 != 0 {
		t.Errorf("regular has group/world permissions: %o", regInfo.Mode())
	}
}

// =============================================================================
// zip extraction tests
// =============================================================================

func createTestZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	zipWriter := zip.NewWriter(&buf)

	for name, content := range files {
		writer, err := zipWriter.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry: %v", err)
		}

		if _, err := writer.Write(content); err != nil {
			t.Fatalf("failed to write zip content: %v", err)
		}
	}

	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

func createZipWithPathTraversal(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	zipWriter := zip.NewWriter(&buf)

	// Malicious entry with path traversal
	writer, err := zipWriter.Create("../../../etc/evil")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}

	if _, err := writer.Write([]byte("evil")); err != nil {
		t.Fatalf("failed to write zip content: %v", err)
	}

	if err := zipWriter.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

func TestExtractAllFromZip_Normal(t *testing.T) {
	t.Parallel()

	data := createTestZip(t, map[string][]byte{
		"file1.txt":     []byte("content1"),
		"dir/file2.txt": []byte("content2"),
	})

	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromZip(data, destDir)
	if err != nil {
		t.Fatalf("extractAllFromZip() error = %v", err)
	}

	// Verify files were extracted
	content1, err := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	if err != nil {
		t.Errorf("failed to read file1.txt: %v", err)
	} else if string(content1) != "content1" {
		t.Errorf("file1.txt content = %q, want %q", content1, "content1")
	}

	content2, err := os.ReadFile(filepath.Join(destDir, "dir/file2.txt"))
	if err != nil {
		t.Errorf("failed to read dir/file2.txt: %v", err)
	} else if string(content2) != "content2" {
		t.Errorf("dir/file2.txt content = %q, want %q", content2, "content2")
	}
}

func TestExtractAllFromZip_PathTraversal(t *testing.T) {
	t.Parallel()

	data := createZipWithPathTraversal(t)
	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromZip(data, destDir)
	if err == nil {
		t.Fatal("extractAllFromZip() should fail on path traversal attempt")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want fault.ErrInvalidArgument", err)
	}
}

// =============================================================================
// Single file extraction tests
// =============================================================================

func TestExtractFileFromTarGz_Normal(t *testing.T) {
	t.Parallel()

	data := createTestTarGz(t, map[string][]byte{
		"bin/mytool":    []byte("binary-content"),
		"README.md":     []byte("readme"),
		"lib/helper.so": []byte("library"),
	})

	release := &HTTPRelease{
		PathInArchive: "bin/mytool",
	}

	extracted, err := release.extractFileFromTarGz(data)
	if err != nil {
		t.Fatalf("extractFileFromTarGz() error = %v", err)
	}

	if string(extracted) != "binary-content" {
		t.Errorf("extracted content = %q, want %q", extracted, "binary-content")
	}
}

func TestExtractFileFromTarGz_FileNotFound(t *testing.T) {
	t.Parallel()

	data := createTestTarGz(t, map[string][]byte{
		"other-file.txt": []byte("content"),
	})

	release := &HTTPRelease{
		PathInArchive: "nonexistent",
	}

	_, err := release.extractFileFromTarGz(data)
	if err == nil {
		t.Fatal("extractFileFromTarGz() should fail when file not found")
	}

	if !errors.Is(err, fault.ErrNotFound) {
		t.Errorf("error = %v, want fault.ErrNotFound", err)
	}
}

func TestExtractFileFromZip_Normal(t *testing.T) {
	t.Parallel()

	data := createTestZip(t, map[string][]byte{
		"bin/mytool":    []byte("binary-content"),
		"README.md":     []byte("readme"),
		"lib/helper.so": []byte("library"),
	})

	release := &HTTPRelease{
		PathInArchive: "bin/mytool",
	}

	extracted, err := release.extractFileFromZip(data)
	if err != nil {
		t.Fatalf("extractFileFromZip() error = %v", err)
	}

	if string(extracted) != "binary-content" {
		t.Errorf("extracted content = %q, want %q", extracted, "binary-content")
	}
}

func TestExtractFileFromZip_FileNotFound(t *testing.T) {
	t.Parallel()

	data := createTestZip(t, map[string][]byte{
		"other-file.txt": []byte("content"),
	})

	release := &HTTPRelease{
		PathInArchive: "nonexistent",
	}

	_, err := release.extractFileFromZip(data)
	if err == nil {
		t.Fatal("extractFileFromZip() should fail when file not found")
	}

	if !errors.Is(err, fault.ErrNotFound) {
		t.Errorf("error = %v, want fault.ErrNotFound", err)
	}
}

// =============================================================================
// Archive format detection tests
// =============================================================================

func TestExtractFile_DetectsFormat(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{
		PathInArchive: "test.txt",
	}

	// Test tar.gz detection
	tarGzData := createTestTarGz(t, map[string][]byte{
		"test.txt": []byte("from-targz"),
	})

	extracted, err := release.extractFile(tarGzData)
	if err != nil {
		t.Fatalf("extractFile(tar.gz) error = %v", err)
	}

	if string(extracted) != "from-targz" {
		t.Errorf("extractFile(tar.gz) = %q, want %q", extracted, "from-targz")
	}

	// Test zip detection
	zipData := createTestZip(t, map[string][]byte{
		"test.txt": []byte("from-zip"),
	})

	extracted, err = release.extractFile(zipData)
	if err != nil {
		t.Fatalf("extractFile(zip) error = %v", err)
	}

	if string(extracted) != "from-zip" {
		t.Errorf("extractFile(zip) = %q, want %q", extracted, "from-zip")
	}
}

func TestExtractFile_UnknownFormat(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{
		PathInArchive: "test.txt",
	}

	// Random data that doesn't match any known format
	unknownData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00}

	_, err := release.extractFile(unknownData)
	if err == nil {
		t.Fatal("extractFile() should fail on unknown format")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want fault.ErrInvalidArgument", err)
	}
}

func TestExtractAll_DetectsFormat(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{}

	// Test tar.gz detection
	tarGzData := createTestTarGz(t, map[string][]byte{
		"file.txt": []byte("content"),
	})

	destDir := t.TempDir()

	err := release.extractAll(tarGzData, destDir)
	if err != nil {
		t.Fatalf("extractAll(tar.gz) error = %v", err)
	}

	// Test zip detection
	zipData := createTestZip(t, map[string][]byte{
		"file.txt": []byte("content"),
	})

	destDir2 := t.TempDir()

	err = release.extractAll(zipData, destDir2)
	if err != nil {
		t.Fatalf("extractAll(zip) error = %v", err)
	}
}

func TestExtractAll_UnknownFormat(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{}

	unknownData := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	err := release.extractAll(unknownData, t.TempDir())
	if err == nil {
		t.Fatal("extractAll() should fail on unknown format")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want fault.ErrInvalidArgument", err)
	}
}

// =============================================================================
// Edge case and stress tests
// =============================================================================

func TestExtractFile_EmptyArchive(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{
		PathInArchive: "nonexistent",
	}

	// Empty tar.gz
	emptyTarGz := createTestTarGz(t, map[string][]byte{})

	_, err := release.extractFileFromTarGz(emptyTarGz)
	if err == nil {
		t.Error("extractFileFromTarGz(empty) should fail")
	}

	// Empty zip
	emptyZip := createTestZip(t, map[string][]byte{})

	_, err = release.extractFileFromZip(emptyZip)
	if err == nil {
		t.Error("extractFileFromZip(empty) should fail")
	}
}

func TestExtractAll_EmptyArchive(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{}

	// Empty tar.gz should succeed (nothing to extract)
	emptyTarGz := createTestTarGz(t, map[string][]byte{})

	err := release.extractAllFromTarGz(emptyTarGz, t.TempDir())
	if err != nil {
		t.Errorf("extractAllFromTarGz(empty) error = %v", err)
	}

	// Empty zip should succeed
	emptyZip := createTestZip(t, map[string][]byte{})

	err = release.extractAllFromZip(emptyZip, t.TempDir())
	if err != nil {
		t.Errorf("extractAllFromZip(empty) error = %v", err)
	}
}

func TestExtract_TruncatedArchive(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{
		PathInArchive: "file.txt",
	}

	// Truncated gzip (just magic bytes)
	truncatedGzip := []byte{0x1f, 0x8b}

	_, err := release.extractFileFromTarGz(truncatedGzip)
	if err == nil {
		t.Error("extractFileFromTarGz(truncated) should fail")
	}

	// Truncated zip (just magic bytes)
	truncatedZip := []byte{0x50, 0x4b, 0x03, 0x04}

	_, err = release.extractFileFromZip(truncatedZip)
	if err == nil {
		t.Error("extractFileFromZip(truncated) should fail")
	}
}

// TestExtractAllFromTarGz_DirectoryCreation verifies that directories from the archive
// are created with correct permissions.
func TestExtractAllFromTarGz_DirectoryCreation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add a directory entry
	dirHeader := &tar.Header{
		Name:     "mydir/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}
	_ = tarWriter.WriteHeader(dirHeader)

	// Add a file in the directory
	fileHeader := &tar.Header{
		Name: "mydir/file.txt",
		Mode: 0o644,
		Size: 4,
	}
	_ = tarWriter.WriteHeader(fileHeader)
	_, _ = tarWriter.Write([]byte("test"))

	_ = tarWriter.Close()
	_ = gzWriter.Close()

	destDir := t.TempDir()
	release := &HTTPRelease{}

	err := release.extractAllFromTarGz(buf.Bytes(), destDir)
	if err != nil {
		t.Fatalf("extractAllFromTarGz() error = %v", err)
	}

	// Verify directory was created with private permissions
	dirInfo, err := os.Stat(filepath.Join(destDir, "mydir"))
	if err != nil {
		t.Fatalf("failed to stat directory: %v", err)
	}

	if !dirInfo.IsDir() {
		t.Error("mydir should be a directory")
	}

	// Directory should have 0700 permissions (private)
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("directory permissions = %o, want 0700", dirInfo.Mode().Perm())
	}
}

// TestMagicBytes verifies that magic byte constants are correct.
func TestMagicBytes(t *testing.T) {
	t.Parallel()

	// Verify gzip magic bytes
	if !bytes.Equal(magicGzip, []byte{0x1f, 0x8b}) {
		t.Errorf("magicGzip = %v, want [0x1f, 0x8b]", magicGzip)
	}

	// Verify zip magic bytes (PK\x03\x04)
	if !bytes.Equal(magicZip, []byte{0x50, 0x4b, 0x03, 0x04}) {
		t.Errorf("magicZip = %v, want [0x50, 0x4b, 0x03, 0x04]", magicZip)
	}
}

// TestExtractFile_VeryShortData ensures we don't panic on data shorter than magic bytes.
func TestExtractFile_VeryShortData(t *testing.T) {
	t.Parallel()

	release := &HTTPRelease{
		PathInArchive: "file.txt",
	}

	// Test with single byte
	_, err := release.extractFile([]byte{0x00})
	if err == nil {
		t.Error("extractFile(single byte) should fail")
	}

	// Test with empty data
	_, err = release.extractFile([]byte{})
	if err == nil {
		t.Error("extractFile(empty) should fail")
	}
}

// =============================================================================
// Decompression bomb simulation tests
// =============================================================================

// Note: We can't easily test the 2GB limit without creating huge test data,
// but we can test that the budget mechanism works correctly.

func TestExtractionBudget_ExactLimit(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(100)
	src := bytes.NewReader(make([]byte, 100))
	dst := &bytes.Buffer{}

	written, err := budget.limitedCopy(dst, src)
	if err != nil {
		t.Errorf("limitedCopy() at exact limit should succeed, got error = %v", err)
	}

	if written != 100 {
		t.Errorf("written = %d, want 100", written)
	}

	if budget.remaining != 0 {
		t.Errorf("budget.remaining = %d, want 0", budget.remaining)
	}
}

func TestExtractionBudget_OneByteTooMany(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(100)
	src := bytes.NewReader(make([]byte, 101))
	dst := &bytes.Buffer{}

	_, err := budget.limitedCopy(dst, src)
	if err == nil {
		t.Error("limitedCopy() with 101 bytes on 100 budget should fail")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want fault.ErrInvalidArgument", err)
	}
}

// TestExtractionBudget_ReaderError ensures we properly wrap reader errors.
func TestExtractionBudget_WriterError(t *testing.T) {
	t.Parallel()

	budget := newExtractionBudget(1000)
	src := bytes.NewReader(make([]byte, 100))
	dst := &failWriter{failAfter: 50}

	_, err := budget.limitedCopy(dst, src)
	if err == nil {
		t.Error("limitedCopy() should propagate writer error")
	}

	if !errors.Is(err, fault.ErrWriteFailure) {
		t.Errorf("error = %v, want fault.ErrWriteFailure", err)
	}
}

// failWriter fails after writing a certain number of bytes.
type failWriter struct {
	written   int
	failAfter int
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.written >= f.failAfter {
		return 0, io.ErrClosedPipe
	}

	canWrite := f.failAfter - f.written
	if canWrite > len(p) {
		canWrite = len(p)
	}

	f.written += canWrite

	if f.written >= f.failAfter {
		return canWrite, io.ErrClosedPipe
	}

	return canWrite, nil
}
