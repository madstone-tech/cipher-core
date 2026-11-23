package crypto

import (
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

// Vector produced by keygen.js (JS-wrapped). Confirms Go can unwrap a
// browser-created key (CLI decrypt compatibility) and that the raw scalar Go
// recovers derives the same public key the browser uploaded.
func TestZKCrossLangJSWrapGoUnwrap(t *testing.T) {
	pass := "correct horse battery staple"
	wrapped, _ := hex.DecodeString("5b144865c45dce919da05642024a2a6d5a5cd0c4ffedc17cb3362d7726e03eee56213ba3aa04ba1e9ee3d388bc5860dc1f5333d80cd1621aa495ce85")
	salt, _ := hex.DecodeString("7d4531a838583d6079b7e565f2befc3a")
	wantPub, _ := hex.DecodeString("89ca51f7e460a72449a3c9564d7880e6df781adae977a443afa0e9b9984e2b1c")
	p := NewArgon2idKEKProvider()
	kek, err := p.DeriveKEK(pass, salt)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := p.UnwrapKey(wrapped, kek, "8d8b2697d06a8e61")
	if err != nil {
		t.Fatalf("Go failed to unwrap JS-wrapped key: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("priv len = %d, want 32", len(priv))
	}
	pk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := pk.PublicKey().Bytes(); hex.EncodeToString(got) != hex.EncodeToString(wantPub) {
		t.Fatalf("derived pub %x != uploaded pub %x", got, wantPub)
	}
	t.Logf("Go unwrapped JS-created key; derived public matches uploaded public ✓")
}
