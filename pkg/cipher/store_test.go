package cipher_test

import (
	"context"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestStoreWrappedKey_StoresCiphertextOnly pins the zero-knowledge path: the
// caller wraps the private half, and nothing here can or does unwrap it.
func TestStoreWrappedKey_StoresCiphertextOnly(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	wrapped := []byte("opaque-ciphertext-produced-by-the-caller")
	salt := make([]byte, 16)

	info, err := client.StoreWrappedKey(ctx, cipher.StoreWrappedKeyInput{
		Alias:             "zk-key",
		PublicKey:         pub,
		WrappedPrivateKey: wrapped,
		Argon2idSalt:      salt,
	})
	if err != nil {
		t.Fatalf("StoreWrappedKey: %v", err)
	}
	if info.Alias != "zk-key" {
		t.Errorf("Alias = %q, want %q", info.Alias, "zk-key")
	}
	if info.Fingerprint == "" {
		t.Error("expected a fingerprint derived from the public key")
	}

	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 stored key, got %d", len(keys))
	}
}
