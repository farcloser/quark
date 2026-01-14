package trust_test

import (
	"encoding/hex"
	"regexp"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/farcloser/quark/pkg/core/trust"
)

func TestGenerateRandomIdentifier_Format(t *testing.T) {
	t.Parallel()

	id := trust.GenerateRandomIdentifier()

	// Should be exactly 8 characters (4 bytes encoded as hex).
	if len(id) != 8 {
		t.Errorf("GenerateRandomIdentifier() returned %d chars, want 8", len(id))
	}

	// Should be valid hex.
	matched, err := regexp.MatchString("^[0-9a-f]{8}$", id)
	if err != nil {
		t.Fatalf("regexp error: %v", err)
	}

	if !matched {
		t.Errorf("GenerateRandomIdentifier() = %q, want lowercase hex", id)
	}
}

func TestGenerateRandomIdentifier_Uniqueness(t *testing.T) {
	t.Parallel()

	const iterations = 1000

	seen := make(map[string]struct{}, iterations)

	for range iterations {
		id := trust.GenerateRandomIdentifier()
		if _, exists := seen[id]; exists {
			t.Fatalf("GenerateRandomIdentifier() produced duplicate: %s", id)
		}

		seen[id] = struct{}{}
	}
}

func TestHashString_Format(t *testing.T) {
	t.Parallel()

	hash := trust.HashString("test input")

	// Should be exactly 16 characters (8 bytes encoded as hex).
	if len(hash) != 16 {
		t.Errorf("HashString() returned %d chars, want 16", len(hash))
	}

	// Should be valid hex.
	matched, err := regexp.MatchString("^[0-9a-f]{16}$", hash)
	if err != nil {
		t.Fatalf("regexp error: %v", err)
	}

	if !matched {
		t.Errorf("HashString() = %q, want lowercase hex", hash)
	}
}

func TestHashString_Deterministic(t *testing.T) {
	t.Parallel()

	input := "consistent input string"
	hash1 := trust.HashString(input)
	hash2 := trust.HashString(input)

	if hash1 != hash2 {
		t.Errorf("HashString() not deterministic: %s != %s", hash1, hash2)
	}
}

func TestHashString_DifferentInputsDifferentOutputs(t *testing.T) {
	t.Parallel()

	hash1 := trust.HashString("input A")
	hash2 := trust.HashString("input B")

	if hash1 == hash2 {
		t.Errorf("HashString() produced same hash for different inputs: %s", hash1)
	}
}

func TestHashString_KnownVector(t *testing.T) {
	t.Parallel()

	// Compute expected value: first 8 bytes of BLAKE2b-256("hello world") as hex.
	fullHash := blake2b.Sum256([]byte("hello world"))
	expected := hex.EncodeToString(fullHash[:8])

	actual := trust.HashString("hello world")

	if actual != expected {
		t.Errorf("HashString(\"hello world\") = %s, want %s", actual, expected)
	}
}

func TestHashString_EmptyString(t *testing.T) {
	t.Parallel()

	// Hash of empty string should still produce valid output.
	hash := trust.HashString("")

	if len(hash) != 16 {
		t.Errorf("HashString(\"\") returned %d chars, want 16", len(hash))
	}

	// Verify against known BLAKE2b-256 of empty string.
	fullHash := blake2b.Sum256([]byte(""))
	expected := hex.EncodeToString(fullHash[:8])

	if hash != expected {
		t.Errorf("HashString(\"\") = %s, want %s", hash, expected)
	}
}

func TestHashString_LongInput(t *testing.T) {
	t.Parallel()

	// Very long input should still work and produce 16-char output.
	longInput := ""
	for range 10000 {
		longInput += "a"
	}

	hash := trust.HashString(longInput)

	if len(hash) != 16 {
		t.Errorf("HashString(long) returned %d chars, want 16", len(hash))
	}
}
