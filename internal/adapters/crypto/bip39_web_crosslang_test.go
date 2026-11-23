package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBIP39WebCrossLang confirms the Go BIP39→X25519 derivation matches the
// browser vector produced by the JS Web Crypto implementation.
func TestBIP39WebCrossLang(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	wantPriv := "12572659c7a55f9a34bd97a309049902653e8db676a93c8e50251676832eff63"
	wantPub := "20066586b4e582ef03c39f9f9bd1029cb631cfc1f0205c47f8f1d6dc0091cf75"

	pub, priv, err := DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("DeriveX25519FromMnemonic: %v", err)
	}
	if hex.EncodeToString(priv) != wantPriv {
		t.Fatalf("priv mismatch\n  go:  %s\n  js:  %s", hex.EncodeToString(priv), wantPriv)
	}
	if hex.EncodeToString(pub) != wantPub {
		t.Fatalf("pub mismatch\n  go:  %s\n  js:  %s", hex.EncodeToString(pub), wantPub)
	}
	t.Logf("BIP39 X25519 derivation matches browser vector OK")
}

// TestBIP39WebCrossLangDeriveWrapRoundTrip verifies that a key wrapped by the
// browser can be unwrapped by Go and equals the deterministically derived scalar.
func TestBIP39WebCrossLangDeriveWrapRoundTrip(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	saltHex := "11111111111111111111111111111111"
	wrappedHex := "222222222222222222222222f601423a1635149a74cd7f86e0afc819828ee375741097cb4481b39f990364257009d5f06b93409f84a4004672af2b88"
	const fixtureKeyID = "web-crosslang-vector" // wrap AAD context (matches fixture regeneration)
	wantPrivHex := "12572659c7a55f9a34bd97a309049902653e8db676a93c8e50251676832eff63"

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	wrapped, err := hex.DecodeString(wrappedHex)
	if err != nil {
		t.Fatalf("decode wrapped: %v", err)
	}
	p := NewArgon2idKEKProvider()
	kek, err := p.DeriveKEK(mnemonic, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	priv, err := p.UnwrapKey(wrapped, kek, fixtureKeyID)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if hex.EncodeToString(priv) != wantPrivHex {
		t.Fatalf("unwrapped priv mismatch\n  got:  %s\n  want: %s", hex.EncodeToString(priv), wantPrivHex)
	}
	// Also verify the unwrapped scalar equals the derived scalar
	_, derivedPriv, err := DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("DeriveX25519FromMnemonic: %v", err)
	}
	if !bytes.Equal(priv, derivedPriv) {
		t.Fatalf("unwrapped priv does not match derived priv\n  unwrapped: %s\n  derived:   %s",
			hex.EncodeToString(priv), hex.EncodeToString(derivedPriv))
	}
	t.Logf("BIP39 derive-wrap-unwrap round-trip matches browser vector OK")
}
