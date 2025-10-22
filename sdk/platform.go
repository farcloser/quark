package sdk

// Platform represents a container platform architecture.
type Platform string

const (
	// PlatformAMD64 represents linux/amd64.
	PlatformAMD64 Platform = "linux/amd64"
	// PlatformARM64 represents linux/arm64.
	PlatformARM64 Platform = "linux/arm64"
)

// String returns the string representation of the platform.
func (platform Platform) String() string {
	return string(platform)
}
