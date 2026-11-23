package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// WrapKeyFixedNonce wraps with a caller-chosen nonce + aad — test-fixture
// regeneration ONLY (deterministic hex vectors). Production WrapKey uses a
// random nonce.
func (p *Argon2idKEKProvider) WrapKeyFixedNonce(privateKey, kek, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, privateKey, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Throwaway: regenerates the zk_crosslang wrapped-key fixture under the
// AAD-bound wrap. Verify-then-copy the printed hex into zk_crosslang_test.go
// and delete this test.
func TestZZGenZKFixture(t *testing.T) {
	pass := "correct horse battery staple"
	saltHex := "7d4531a838583d6079b7e565f2befc3a"
	salt, _ := hex.DecodeString(saltHex)
	p := NewArgon2idKEKProvider()
	kek, err := p.DeriveKEK(pass, salt)
	if err != nil {
		t.Fatal(err)
	}
	// Scalar for wantPub: derive from a known source? The fixture's priv is the
	// X25519 scalar whose public is wantPub. Recover it: scalar = clamp(priv) —
	// not invertible. Instead: regenerate with a fixed keypair and REWRITE the
	// wantPub in the test too. Use deterministic derivation from the salt:
	_, priv, err := deriveScalarDeterministic(kek) // helper below
	if err != nil {
		t.Fatal(err)
	}
	keyID := "6d80027bf3deb533"                              // matches hex(sha256(wantPub))[:16] — but pub changes with the new scalar; recompute below
	nonce, _ := hex.DecodeString("5b144865c45dce919da05642") // 12 bytes from original wrapped prefix? keep deterministic: fixed
	wrapped, err := p.WrapKeyFixedNonce(priv, kek, nonce, []byte("mdstn-wrapped-key:"+keyID))
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ecdh.X25519().NewPrivateKey(priv)
	fmt.Printf("wrappedHex: %s\nsaltHex unchanged\nwantPubHex: %s\nkeyID: %s\n",
		hex.EncodeToString(wrapped), hex.EncodeToString(pk.PublicKey().Bytes()), keyID)
}

func deriveScalarDeterministic(kek []byte) (pub, priv []byte, err error) {
	h := sha256.Sum256(append(kek, []byte("063-zk-fixture-scalar")...))
	priv = h[:]
	e, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return e.PublicKey().Bytes(), priv, nil
}

func ecdhPubForTest(priv []byte) (pub []byte, err error) {
	e, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return e.PublicKey().Bytes(), nil
}

func hexSha256Prefix16(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}
