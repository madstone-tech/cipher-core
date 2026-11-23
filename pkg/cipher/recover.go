package cipher

import (
	"context"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
)

// DeriveFromMnemonic derives the X25519 keypair from a 24-word BIP39
// mnemonic without storing anything. The derivation is frozen:
// mnemonic → BIP39 seed → HKDF-SHA256(info="cipher-x25519-v1") → 32-byte
// scalar → X25519. Changing the info string breaks recovery for every
// existing identity (it is pinned by test vectors).
//
// This function is pure — no repository or session interaction — so it is
// also the reference for cross-language reimplementation of the derivation.
func DeriveFromMnemonic(mnemonic string) (publicKey, privateKey []byte, err error) {
	return crypto.DeriveX25519FromMnemonic(mnemonic)
}

// RecoverFromMnemonic restores an identity from a 24-word BIP39 phrase: it
// derives the keypair (see DeriveFromMnemonic) and stores the private key
// wrapped with the given key passphrase (Argon2id) in the local store.
//
// The mnemonic itself is never stored; only the derived, wrapped key.
func (c *Client) RecoverFromMnemonic(ctx context.Context, mnemonic, keyPassphrase string) (*KeyInfo, error) {
	key, err := c.recoverUC.RecoverFromMnemonicWith(
		ctx,
		mnemonic,
		keyPassphrase,
		crypto.DeriveX25519FromMnemonic,
	)
	if err != nil {
		return nil, fmt.Errorf("cipher: recover: %w", err)
	}
	return toKeyInfo(key), nil
}
