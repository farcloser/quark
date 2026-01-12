package types

import (
	"fmt"
	"strings"
)

// Platform represents a container platform (OS/architecture/variant).
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	OSFeatures   string `json:"os.features,omitempty"`
	OSVersion    string `json:"os.version,omitempty"`
	// Reserved for future use
	Features string `json:"features,omitempty"`
}

//nolint:gochecknoglobals // Platform enum pattern requires global variables.
var (
	// AMD64 represents linux/amd64.
	AMD64 = &Platform{OS: "linux", Architecture: "amd64"}
	// ARM64 represents linux/arm64.
	ARM64   = &Platform{OS: "linux", Architecture: "arm64"}
	Unknown = &Platform{OS: "unknown", Architecture: "unknown"}
	// NoExplicitPlatform is a convenience alias to not specifying any platform.
	NoExplicitPlatform = []*Platform{}
)

// String returns the string representation of the platform (e.g., "linux/amd64" or "linux/arm64/v8").
func (p *Platform) String() string {
	result := fmt.Sprintf("%s/%s", p.OS, p.Architecture)
	if p.Variant != "" {
		result += "/" + p.Variant
	}

	return result
}

// Matches returns true if this platform matches another.
// A nil variant matches any variant.
func (p *Platform) Matches(other *Platform) bool {
	if p == nil || other == nil {
		return false
	}

	if p.OS != other.OS || p.Architecture != other.Architecture {
		return false
	}

	// If either variant is empty, consider it a match.
	if p.Variant == "" || other.Variant == "" {
		return true
	}

	return p.Variant == other.Variant
}

// ParsePlatform parses a platform string (e.g., "linux/amd64" or "linux/arm64/v8").
func ParsePlatform(s string) (*Platform, error) {
	parts := strings.Split(s, "/")

	switch len(parts) {
	case 2:
		return &Platform{
			OS:           parts[0],
			Architecture: parts[1],
		}, nil
	case 3:
		return &Platform{
			OS:           parts[0],
			Architecture: parts[1],
			Variant:      parts[2],
		}, nil
	default:
		return nil, fmt.Errorf("invalid platform format %q: expected os/arch or os/arch/variant", s)
	}
}
