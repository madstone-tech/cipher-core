package crypto

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestGenerateMnemonic(t *testing.T) {
	m1, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}

	if !bip39.IsMnemonicValid(m1) {
		t.Fatalf("mnemonic not valid: %q", m1)
	}

	words := strings.Fields(m1)
	if len(words) != 24 {
		t.Fatalf("expected 24 words, got %d", len(words))
	}

	m2, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("second GenerateMnemonic: %v", err)
	}

	if m1 == m2 {
		t.Fatal("two calls to GenerateMnemonic returned identical results")
	}
}
