package crypto

import (
	"bytes"
	"testing"
)

// TestBIP39WebUnifiedWrapRoundTrip verifies the unified BIP39 derive→wrap→unwrap
// path: GenerateMnemonic produces a valid mnemonic, DeriveX25519FromMnemonic
// produces a scalar, which is then wrapped with an Argon2id KEK derived from a
// key passphrase + fresh salt, and UnwrapKey recovers the original scalar exactly.
func TestBIP39WebUnifiedWrapRoundTrip(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	_, derivedPriv, err := DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("DeriveX25519FromMnemonic: %v", err)
	}

	p := NewArgon2idKEKProvider()

	salt, err := p.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	const keyPassphrase = "test-key-passphrase-for-wrap-round-trip"

	kek, err := p.DeriveKEK(keyPassphrase, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}

	wrapped, err := p.WrapKey(derivedPriv, kek, "unified-test-key")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	recovered, err := p.UnwrapKey(wrapped, kek, "unified-test-key")
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if !bytes.Equal(recovered, derivedPriv) {
		t.Fatalf("recovered scalar does not match derived scalar")
	}

	t.Logf("BIP39 unified derive-wrap-unwrap round-trip OK")
}
