package crypto

import (
	"bytes"
	"testing"
)

func TestKEKProvider_RoundTrip(t *testing.T) {
	p := NewArgon2idKEKProvider()

	salt, err := p.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	kek, err := p.DeriveKEK("test-passphrase", salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if len(kek) != 32 {
		t.Fatalf("KEK length: got %d, want 32", len(kek))
	}

	privateKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	wrapped, err := p.WrapKey(privateKey, kek, "test-key-id")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	// Wrapped should be longer than original (nonce + tag overhead)
	if len(wrapped) <= len(privateKey) {
		t.Fatalf("wrapped length %d should be > original %d", len(wrapped), len(privateKey))
	}

	unwrapped, err := p.UnwrapKey(wrapped, kek, "test-key-id")
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if !bytes.Equal(unwrapped, privateKey) {
		t.Fatalf("round-trip failed: got %x, want %x", unwrapped, privateKey)
	}
}

func TestKEKProvider_SaltLength(t *testing.T) {
	p := NewArgon2idKEKProvider()
	salt, err := p.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("salt length: got %d, want 16", len(salt))
	}
}

func TestKEKProvider_WrongKEK(t *testing.T) {
	p := NewArgon2idKEKProvider()

	salt, _ := p.GenerateSalt()
	kek1, _ := p.DeriveKEK("correct-passphrase", salt)
	kek2, _ := p.DeriveKEK("wrong-passphrase", salt)

	privateKey := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := p.WrapKey(privateKey, kek1, "test-key-id")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	_, err = p.UnwrapKey(wrapped, kek2, "test-key-id")
	if err == nil {
		t.Fatal("UnwrapKey with wrong KEK should fail")
	}
}

func TestKEKProvider_ZeroKEK(t *testing.T) {
	p := NewArgon2idKEKProvider()
	kek := []byte("0123456789abcdef0123456789abcdef")
	p.ZeroKEK(kek)

	for i, b := range kek {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestKEKProvider_EmptyPassphrase(t *testing.T) {
	p := NewArgon2idKEKProvider()
	salt, _ := p.GenerateSalt()
	_, err := p.DeriveKEK("", salt)
	if err == nil {
		t.Fatal("DeriveKEK with empty passphrase should fail")
	}
}

func TestKEKProvider_DeterministicDerivation(t *testing.T) {
	p := NewArgon2idKEKProvider()
	salt, _ := p.GenerateSalt()

	kek1, _ := p.DeriveKEK("same-passphrase", salt)
	kek2, _ := p.DeriveKEK("same-passphrase", salt)

	if !bytes.Equal(kek1, kek2) {
		t.Fatal("same passphrase + salt should produce identical KEKs")
	}
}
