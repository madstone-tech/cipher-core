package crypto

import "github.com/tyler-smith/go-bip39"

// Engine implements the CryptoEngine interface
type Engine struct{}

// NewEngine creates a new crypto engine
func NewEngine() *Engine {
	return &Engine{}
}

// GenerateMnemonic generates a cryptographically random BIP39 24-word mnemonic.
func (a *Engine) GenerateMnemonic() (string, error) {
	return GenerateMnemonic()
}

// DeriveX25519FromMnemonic deterministically derives an X25519 keypair from a BIP39 mnemonic.
func (a *Engine) DeriveX25519FromMnemonic(mnemonic string) (publicKey, privateKey []byte, err error) {
	return DeriveX25519FromMnemonic(mnemonic)
}

// IsValidMnemonic reports whether mnemonic is a valid BIP39 phrase.
func (a *Engine) IsValidMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}
