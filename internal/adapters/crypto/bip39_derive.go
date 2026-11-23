package crypto

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

// DeriveX25519FromMnemonic deterministically derives an X25519 keypair
// from a BIP39 mnemonic. The derivation path is:
//
//	mnemonic → BIP39 seed (no passphrase) → HKDF-SHA256(info="cipher-x25519-v1") → 32-byte private key → public key
func DeriveX25519FromMnemonic(mnemonic string) (publicKey, privateKey []byte, err error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("invalid BIP39 mnemonic")
	}

	// BIP39 seed derivation (64 bytes) with empty passphrase
	seed := bip39.NewSeed(mnemonic, "")

	// HKDF-SHA256 to derive 32-byte X25519 private key
	hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("cipher-x25519-v1"))
	privBytes := make([]byte, 32)
	if _, err := hkdfReader.Read(privBytes); err != nil {
		return nil, nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	// Derive public key via crypto/ecdh
	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}

	return privKey.PublicKey().Bytes(), privBytes, nil
}
