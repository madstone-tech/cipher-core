package entities

import "time"

// CKDEntry is a trust-on-first-use (TOFU) cache record for a discovered CKD
// public key. The cache MUST use (EmailHash, key_type) as a composite key for
// future multi-key-type support.
//
// TrustLevel: 0 = untrusted, 1 = TOFU-accepted, 2+ = explicitly trusted.
type CKDEntry struct {
	EmailHash   string
	PublicKey   []byte
	Fingerprint string
	FirstSeen   time.Time
	LastSeen    time.Time
	TrustLevel  int
}
