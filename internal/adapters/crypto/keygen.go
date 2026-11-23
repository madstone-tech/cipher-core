package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateAESKey generates a new 256-bit AES key
func (e *Engine) GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// Hash computes SHA-256 hash and returns hex string
func (e *Engine) Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CompareFingerprints compares two fingerprint strings using constant-time
// comparison to prevent timing side-channel attacks.
func CompareFingerprints(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CompareKeys compares two raw key byte slices using constant-time comparison.
// Returns true if and only if a and b have identical length and content.
func CompareKeys(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
