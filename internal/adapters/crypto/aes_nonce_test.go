package crypto

import (
	"bytes"
	"testing"
)

// TestHostileNonceLengthIsAnError checks that a wrong-length nonce from a
// hostile header gives an error, not a gcm.Open panic. The recipient-block
// "nonce" is length-checked by the decoder; the engine checks it too.
func TestHostileNonceLengthIsAnError(t *testing.T) {
	e := NewEngine()
	key := bytes.Repeat([]byte{7}, 32)
	_, priv, err := e.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	eph, _, err := e.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, 48)

	for _, n := range []int{0, 5, 11, 13, 32} {
		nonce := make([]byte, n)
		mustError(t, "DecryptAES", func() error {
			_, err := e.DecryptAES(ct, key, nonce, nil)
			return err
		})
		mustError(t, "DecryptX25519", func() error {
			_, err := e.DecryptX25519(ct, eph, nonce, priv, nil)
			return err
		})
		mustError(t, "UnwrapCEK", func() error {
			_, err := e.UnwrapCEK(ct, eph, nonce, priv, nil)
			return err
		})
	}
}

func mustError(t *testing.T, name string, f func() error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	if f() == nil {
		t.Fatalf("%s: want an error for a wrong nonce length", name)
	}
}
