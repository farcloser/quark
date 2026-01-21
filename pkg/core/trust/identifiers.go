package trust

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/farcloser/quark/pkg/fault"
)

// GenerateRandomIdentifier returns a reasonably collision resistant transient identifier.
// This is typically used to generate a socket path, or build identifiers.
// Chances of collisions are 50% for 65k simultaneous.
// This is NOT a good choice for persistent data storage, and is meant to be used for transient operations only.
func GenerateRandomIdentifier() string {
	// 50% collision at √(2^32) = √4,294,967,296 ≈ 65,536 concurrent processes
	var buf [4]byte

	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Errorf("%w: failed to generate process token: %w", fault.ErrSystemFailure, err))
	}

	return hex.EncodeToString(buf[:])
}

// HashString returns an 8-byte (16 hex char) hash of the input string.
// Useful for example to keep Unix socket paths under OS limits (104 bytes on macOS),
// or more generally to derive identifiers that are reasonably collision resistant.
// 50% collision probability at ~5 billion items.
// 1% probability at ~607 million.
func HashString(s string) string {
	hash := blake2b.Sum256([]byte(s))

	return hex.EncodeToString(hash[:8])
}
