package version_test

import (
	"testing"

	"github.com/farcloser/quark/pkg/version"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	v := version.Version()

	if v == "" {
		t.Error("Version() should not return empty string")
	}

	// Default version should be semantic version format
	// At minimum it should contain a dot (e.g., "0.1.0")
	hasDot := false

	for _, c := range v {
		if c == '.' {
			hasDot = true

			break
		}
	}

	if !hasDot {
		t.Errorf("Version() = %q, expected semantic version format with dot", v)
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	n := version.Name()

	if n == "" {
		t.Error("Name() should not return empty string")
	}

	// Name should be lowercase identifier
	for _, c := range n {
		if c >= 'A' && c <= 'Z' {
			t.Errorf("Name() = %q, expected lowercase", n)

			break
		}
	}
}

func TestVersion_Consistency(t *testing.T) {
	t.Parallel()

	// Multiple calls should return same value
	v1 := version.Version()
	v2 := version.Version()

	if v1 != v2 {
		t.Errorf("Version() not consistent: %q != %q", v1, v2)
	}
}

func TestName_Consistency(t *testing.T) {
	t.Parallel()

	// Multiple calls should return same value
	n1 := version.Name()
	n2 := version.Name()

	if n1 != n2 {
		t.Errorf("Name() not consistent: %q != %q", n1, n2)
	}
}

func TestVersion_DefaultValue(t *testing.T) {
	t.Parallel()

	// Without ldflags override, should return default
	v := version.Version()

	// Just verify it's a valid semver-like string
	if len(v) < 5 { // "0.0.0" is minimum
		t.Errorf("Version() = %q, expected at least 5 characters", v)
	}
}

func TestName_DefaultValue(t *testing.T) {
	t.Parallel()

	n := version.Name()

	// Default should be "quark"
	if n != "quark" {
		t.Errorf("Name() = %q, expected %q", n, "quark")
	}
}
