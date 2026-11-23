package cipher

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns the hex SHA-256 fingerprint of a public key — the same
// convention every Cipher surface uses to identify keys.
func Fingerprint(publicKey []byte) string {
	h := sha256.Sum256(publicKey)
	return hex.EncodeToString(h[:])
}
