package crypto

import (
	"bytes"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestDeriveX25519FromMnemonic_Deterministic(t *testing.T) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	pub1, priv1, err := DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}

	pub2, priv2, err := DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}

	if !bytes.Equal(pub1, pub2) {
		t.Fatal("same mnemonic should produce same public key")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Fatal("same mnemonic should produce same private key")
	}
	if len(priv1) != 32 {
		t.Fatalf("private key length: got %d, want 32", len(priv1))
	}
	if len(pub1) != 32 {
		t.Fatalf("public key length: got %d, want 32", len(pub1))
	}
}

func TestDeriveX25519FromMnemonic_DifferentMnemonics(t *testing.T) {
	entropy1, _ := bip39.NewEntropy(256)
	mnemonic1, _ := bip39.NewMnemonic(entropy1)

	entropy2, _ := bip39.NewEntropy(256)
	mnemonic2, _ := bip39.NewMnemonic(entropy2)

	pub1, _, _ := DeriveX25519FromMnemonic(mnemonic1)
	pub2, _, _ := DeriveX25519FromMnemonic(mnemonic2)

	if bytes.Equal(pub1, pub2) {
		t.Fatal("different mnemonics should produce different public keys")
	}
}

func TestDeriveX25519FromMnemonic_InvalidMnemonic(t *testing.T) {
	_, _, err := DeriveX25519FromMnemonic("invalid words that are not a mnemonic")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}
