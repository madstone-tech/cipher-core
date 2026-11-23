package cipher_test

import (
	"encoding/hex"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestDerivationPin freezes the BIP39 → X25519 derivation compatibility
// surface. The all-abandon mnemonic (canonical BIP39 test vector) must yield
// this exact public key and fingerprint under the frozen derivation:
//
//	mnemonic → BIP39 seed → HKDF-SHA256(info="cipher-x25519-v1") → scalar → X25519
//
// Any change to the derivation (the info string, the hash, the encoding)
// breaks key recovery for every existing identity. If this test fails, the
// derivation changed — do NOT update the pin without a governance-reviewed
// format decision (docs/format-spec.md §Governance).
func TestDerivationPin(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Frozen values — computed from the frozen derivation on 2026-09-05
	// and cross-checked against the CLI's `recover from-mnemonic` output.
	const wantPubHex = "20066586b4e582ef03c39f9f9bd1029cb631cfc1f0205c47f8f1d6dc0091cf75"
	const wantFingerprint = "90be2125e75c7c54434a697cbf2533e2f6ac2dbb82161e92932682ace0c75722"

	pub, _, err := cipher.DeriveFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("DeriveFromMnemonic: %v", err)
	}
	if got := hex.EncodeToString(pub); got != wantPubHex {
		t.Fatalf("derived public key changed:\n  got  %s\n  want %s\n"+
			"The derivation compatibility surface is FROZEN — see format-spec §Governance.", got, wantPubHex)
	}
	if got := cipher.Fingerprint(pub); got != wantFingerprint {
		t.Fatalf("fingerprint changed:\n  got  %s\n  want %s", got, wantFingerprint)
	}
}

// TestFingerprintConvention pins the fingerprint helper against the
// engine's Hash convention (SHA-256 hex of the public key).
func TestFingerprintConvention(t *testing.T) {
	// SHA-256 of empty input, hex-encoded — a stable convention check.
	if got := cipher.Fingerprint(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("Fingerprint(nil) = %q, want SHA-256 of empty input", got)
	}
}
