package crypto

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// GenerateMnemonic generates a cryptographically random BIP39 24-word mnemonic
// phrase backed by 256 bits of entropy.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generate mnemonic: %w", err)
	}

	return mnemonic, nil
}
