package platform

// Platform represents a container platform architecture.
type Platform struct {
	value string
}

//nolint:gochecknoglobals // Platform enum pattern requires global variables
var (
	// AMD64 represents linux/amd64.
	AMD64 = Platform{"linux/amd64"}
	// ARM64 represents linux/arm64.
	ARM64 = Platform{"linux/arm64"}
)

// String returns the string representation of the platform.
func (platform Platform) String() string {
	return platform.value
}
