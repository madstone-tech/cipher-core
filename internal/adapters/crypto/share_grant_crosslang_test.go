package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Vector produced by a JS reference implementation's wrap (a browser-based
// zero-knowledge "share key" flow). It confirms that a grant the browser
// produces — packed as ephemeral_pub(32) || nonce(12) || AES-256-GCM(key) and
// derived via X25519 ECDH → HKDF-SHA256(info="mdstn-cipher-x25519") — decrypts
// with the Go engine (so the CLI/usecase can read web-created shares) and that
// the key_hash the browser sends matches sha256(rawKey) the way
// ManageTeamKeys.DecryptGrantedKey verifies it.
func TestShareGrantCrossLangJSWrapGoUnwrap(t *testing.T) {
	recipientPriv, _ := hex.DecodeString("78fd75303c1fa0a9bf591e90a8ab45c3bb83483d2cf50565efc16dde38577047")
	wantRawKey, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	wantKeyHash := "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
	packed, err := base64.StdEncoding.DecodeString(
		"FJNdAvQBQ65agQjzBci4etQddRfs0aNpeHWL5JvYk3tS1IgKkoyOa6D+xmk4ebGi9Dc/Xi+lpoz++M9LaUDU51x3RRYWbRaJsm2Lq1TGSDDn3Ss1S89iXT8tXS4=")
	if err != nil {
		t.Fatalf("decode packed vector: %v", err)
	}

	// Unpack exactly as ManageTeamKeys.DecryptGrantedKey does.
	if len(packed) < 44 {
		t.Fatalf("packed too short: %d", len(packed))
	}
	ephPub := packed[:32]
	nonce := packed[32:44]
	ciphertext := packed[44:]

	engine := NewEngine()
	rawKey, err := engine.DecryptX25519(ciphertext, ephPub, nonce, recipientPriv, nil)
	if err != nil {
		t.Fatalf("Go failed to decrypt JS-wrapped grant: %v", err)
	}
	if hex.EncodeToString(rawKey) != hex.EncodeToString(wantRawKey) {
		t.Fatalf("decrypted key %x != expected %x", rawKey, wantRawKey)
	}

	hash := sha256.Sum256(rawKey)
	if hex.EncodeToString(hash[:]) != wantKeyHash {
		t.Fatalf("key_hash %x != browser-sent %s", hash[:], wantKeyHash)
	}
	t.Logf("Go decrypted JS-created share grant; key + key_hash match ✓")
}
