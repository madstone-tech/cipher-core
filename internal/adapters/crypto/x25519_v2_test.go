package crypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// wrapWithKDF wraps cek like WrapCEK, but derives the KEK from the shared
// secret with recipientPub and the given HKDF salt and info, so a test can
// build blocks that the v2 KDF must reject.
func wrapWithKDF(t *testing.T, cek, recipientPub, salt, info, aad []byte, ephPriv []byte) (ephPub, nonce, wrapped []byte) {
	t.Helper()
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, info), kek); err != nil {
		t.Fatal(err)
	}
	wrapped, nonce, err = NewEngine().EncryptAES(cek, kek, aad)
	if err != nil {
		t.Fatal(err)
	}
	return ephPub, nonce, wrapped
}

func TestWrapCEKv2BindsKeys(t *testing.T) {
	engine := NewEngine()
	aad := []byte(entities.WrapCEKAAD)
	pub1, priv1, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cek := randomKey(t)

	eph, nonce, wrapped, err := engine.WrapCEK(cek, pub1, aad)
	if err != nil {
		t.Fatalf("WrapCEK: %v", err)
	}
	if len(eph) != 32 || len(nonce) != 12 || len(wrapped) != 48 {
		t.Fatalf("block sizes = %d/%d/%d, want 32/12/48", len(eph), len(nonce), len(wrapped))
	}

	t.Run("control: unwrap opens", func(t *testing.T) {
		got, err := engine.UnwrapCEK(wrapped, eph, nonce, priv1, aad)
		if err != nil {
			t.Fatalf("UnwrapCEK: %v", err)
		}
		if !bytes.Equal(got, cek) {
			t.Fatal("unwrapped CEK differs")
		}
	})

	t.Run("retired unsalted KDF block fails", func(t *testing.T) {
		// The retired 0x01 wrap: HKDF without salt, info "mdstn-cipher-x25519".
		e1, n1, w1 := wrapWithKDF(t, cek, pub1, nil, []byte("mdstn-cipher-x25519"), aad, randomKey(t))
		if _, err := engine.UnwrapCEK(w1, e1, n1, priv1, aad); err == nil {
			t.Fatal("UnwrapCEK opened a block made with the retired KDF")
		}
	})

	t.Run("block for another recipient fails", func(t *testing.T) {
		if _, err := engine.UnwrapCEK(wrapped, eph, nonce, priv2, aad); err == nil {
			t.Fatal("recipient 2 opened a block for recipient 1")
		}
	})

	t.Run("block re-targeted to another recipient public key fails", func(t *testing.T) {
		// The X25519 output is the one recipient 1 computes, but the KEK salt
		// names recipient 2: the KDF binds R_pub, so recipient 1 must fail.
		ephPriv := randomKey(t)
		ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		salt := append(append([]byte{}, ephPub...), pub2...)
		e, n, w := wrapWithKDF(t, cek, pub1, salt, []byte("mdstn-cipher/v2/wrap"), aad, ephPriv)
		if _, err := engine.UnwrapCEK(w, e, n, priv1, aad); err == nil {
			t.Fatal("a block with R_pub of recipient 2 in the KDF opened for recipient 1")
		}
		// Control: the same construction with recipient 1 in the salt opens.
		salt = append(append([]byte{}, ephPub...), pub1...)
		e, n, w = wrapWithKDF(t, cek, pub1, salt, []byte("mdstn-cipher/v2/wrap"), aad, ephPriv)
		if _, err := engine.UnwrapCEK(w, e, n, priv1, aad); err != nil {
			t.Fatalf("control: the documented KDF does not match UnwrapCEK: %v", err)
		}
	})

	t.Run("wrong wrap AAD fails", func(t *testing.T) {
		if _, err := engine.UnwrapCEK(wrapped, eph, nonce, priv1, []byte("mdstn-wrap-cek")); err == nil {
			t.Fatal("block opened with the retired wrap AAD")
		}
	})

	t.Run("low-order ephemeral key is rejected", func(t *testing.T) {
		if _, err := engine.UnwrapCEK(wrapped, make([]byte, 32), nonce, priv1, aad); err == nil {
			t.Fatal("all-zero ephemeral key accepted")
		}
		if _, _, _, err := engine.WrapCEK(cek, make([]byte, 32), aad); err == nil {
			t.Fatal("WrapCEK accepted an all-zero recipient key")
		}
	})

	t.Run("non-canonical recipient key is rejected by WrapCEK", func(t *testing.T) {
		bit255 := append([]byte{}, pub1...)
		bit255[31] |= 0x80
		if _, _, _, err := engine.WrapCEK(cek, bit255, aad); !errors.Is(err, entities.ErrInvalidRecipientKey) {
			t.Fatalf("WrapCEK with bit 255 set: err = %v, want ErrInvalidRecipientKey", err)
		}
	})
}
