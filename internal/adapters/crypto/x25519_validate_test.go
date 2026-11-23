package crypto

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// TestValidatePublicKeyCanonical checks FR-004 (R4): a recipient public key
// is 32 bytes, has bit 255 clear, encodes u < 2^255 - 19 (little-endian), and
// is not a low-order point. Every failure matches ErrInvalidRecipientKey.
func TestValidatePublicKeyCanonical(t *testing.T) {
	pub, _, err := NewEngine().GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(pub); err != nil {
		t.Fatalf("real key: %v", err)
	}

	bit255 := append([]byte{}, pub...)
	bit255[31] |= 0x80

	le := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad test point %q", s)
		}
		return b
	}
	cases := map[string][]byte{
		"bit 255 set":         bit255,
		"u = p":               le("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"u = p + 1":           le("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"u = 2^255 - 1":       le("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"low order: 0":        make([]byte, 32),
		"low order: 1":        le("0100000000000000000000000000000000000000000000000000000000000000"),
		"low order: p - 1":    le("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"low order: order 8":  le("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		"low order: order 8'": le("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		"31 bytes":            pub[:31],
		"33 bytes":            append(append([]byte{}, pub...), 0),
		"empty":               nil,
	}
	for name, key := range cases {
		err := ValidatePublicKey(key)
		if !errors.Is(err, entities.ErrInvalidRecipientKey) {
			t.Errorf("%s: err = %v, want ErrInvalidRecipientKey", name, err)
		}
	}
}
