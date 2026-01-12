package version

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tag         string
		wantPrefix  string
		wantVersion string
		wantSuffix  string
	}{
		// Plain versions
		{tag: "1.2.3", wantPrefix: "", wantVersion: "1.2.3", wantSuffix: ""},
		{tag: "v1.2.3", wantPrefix: "", wantVersion: "1.2.3", wantSuffix: ""},
		{tag: "0.51.1", wantPrefix: "", wantVersion: "0.51.1", wantSuffix: ""},
		{tag: "v2.9.13", wantPrefix: "", wantVersion: "2.9.13", wantSuffix: ""},

		// Versions with suffix
		{tag: "1.2.3-alpine", wantPrefix: "", wantVersion: "1.2.3", wantSuffix: "alpine"},
		{tag: "20.2.3-alpine", wantPrefix: "", wantVersion: "20.2.3", wantSuffix: "alpine"},
		{tag: "v1.2.3-alpine", wantPrefix: "", wantVersion: "1.2.3", wantSuffix: "alpine"},
		{tag: "0.51.1-distroless-static", wantPrefix: "", wantVersion: "0.51.1", wantSuffix: "distroless-static"},

		// Versions with prefix (date-based)
		{tag: "trixie-2025-11-29", wantPrefix: "trixie", wantVersion: "2025.11.29", wantSuffix: ""},
		{tag: "bookworm-2025-05-01", wantPrefix: "bookworm", wantVersion: "2025.05.01", wantSuffix: ""},

		// Versions with prefix (name-based)
		{tag: "server-1.2.3", wantPrefix: "server", wantVersion: "1.2.3", wantSuffix: ""},
		{tag: "bridge-v2.0.0", wantPrefix: "bridge", wantVersion: "2.0.0", wantSuffix: ""},

		// Complex: prefix and suffix
		{tag: "server-v1.2.3-alpine", wantPrefix: "server", wantVersion: "1.2.3", wantSuffix: "alpine"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			t.Parallel()

			got := parseVersion(tt.tag)

			if got.Prefix != tt.wantPrefix {
				t.Errorf("parseVersion(%q).Prefix = %q, want %q", tt.tag, got.Prefix, tt.wantPrefix)
			}

			if got.Version != tt.wantVersion {
				t.Errorf("parseVersion(%q).Version = %q, want %q", tt.tag, got.Version, tt.wantVersion)
			}

			if got.Suffix != tt.wantSuffix {
				t.Errorf("parseVersion(%q).Suffix = %q, want %q", tt.tag, got.Suffix, tt.wantSuffix)
			}
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tag    string
		filter string
		want   bool
	}{
		// No filter: only plain versions match
		{tag: "1.2.3", filter: "", want: true},
		{tag: "v1.2.3", filter: "", want: true},
		{tag: "1.2.3-alpine", filter: "", want: false},
		{tag: "trixie-2025-11-29", filter: "", want: false},

		// Filter by suffix
		{tag: "1.2.3-alpine", filter: "alpine", want: true},
		{tag: "v1.2.3-alpine", filter: "alpine", want: true},
		{tag: "1.2.3-slim", filter: "alpine", want: false},
		{tag: "1.2.3", filter: "alpine", want: false},
		{tag: "0.51.1-distroless-static", filter: "distroless-static", want: true},

		// Filter by prefix
		{tag: "trixie-2025-11-29", filter: "trixie", want: true},
		{tag: "bookworm-2025-05-01", filter: "trixie", want: false},
		{tag: "bookworm-2025-05-01", filter: "bookworm", want: true},
		{tag: "server-1.2.3", filter: "server", want: true},

		// Exclude patterns
		{tag: "1.2.3-beta", filter: "", want: false},
		{tag: "1.2.3-rc1", filter: "", want: false},
		{tag: "nightly-2025-01-01", filter: "", want: false},
		{tag: "v1.2.3-alpha", filter: "alpha", want: false},
		{tag: "1.2.3-dev", filter: "dev", want: false},
	}

	for _, tt := range tests {
		name := tt.tag
		if tt.filter != "" {
			name += "_filter_" + tt.filter
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := isValidVersion(tt.tag, tt.filter)
			if got != tt.want {
				t.Errorf("isValidVersion(%q, %q) = %v, want %v", tt.tag, tt.filter, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		v1   string
		v2   string
		want int // -1: v1 < v2, 0: equal, 1: v1 > v2
	}{
		// Plain versions
		{v1: "1.2.3", v2: "1.2.4", want: -1},
		{v1: "1.2.4", v2: "1.2.3", want: 1},
		{v1: "1.2.3", v2: "1.2.3", want: 0},
		{v1: "1.2.3", v2: "1.3.0", want: -1},
		{v1: "1.2.3", v2: "2.0.0", want: -1},
		{v1: "v1.2.3", v2: "v1.2.4", want: -1},

		// Date-based versions (hyphens become dots for comparison)
		{v1: "trixie-2025-11-29", v2: "trixie-2025-11-30", want: -1},
		{v1: "trixie-2025-11-30", v2: "trixie-2025-11-29", want: 1},
		{v1: "trixie-2025-11-29", v2: "trixie-2025-11-29", want: 0},
		{v1: "bookworm-2025-05-01", v2: "bookworm-2025-06-01", want: -1},

		// Versions with suffix
		{v1: "1.2.3-alpine", v2: "1.2.4-alpine", want: -1},
		{v1: "0.51.0-distroless-static", v2: "0.51.1-distroless-static", want: -1},
	}

	for _, tt := range tests {
		name := tt.v1 + "_vs_" + tt.v2

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := compareVersions(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}
