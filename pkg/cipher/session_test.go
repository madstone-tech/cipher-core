package cipher_test

import (
	"context"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestUnlockThenLock pins the ssh-agent-style lifecycle: a correct passphrase
// caches the KEK, a wrong one is rejected rather than cached, and both lock
// calls clear cleanly.
func TestUnlockThenLock(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	created, err := client.CreateKey(ctx, "session-key", "key-passphrase-123")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if err := client.Unlock(ctx, created.Key.ID, "key-passphrase-123"); err != nil {
		t.Fatalf("Unlock with the correct passphrase: %v", err)
	}

	if err := client.Unlock(ctx, created.Key.ID, "wrong-passphrase"); err == nil {
		t.Fatal("Unlock accepted a wrong passphrase; a bad KEK must never be cached")
	}

	if err := client.Lock(created.Key.ID); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := client.LockAll(); err != nil {
		t.Fatalf("LockAll: %v", err)
	}
}

func TestUnlockRejectsEmptyInput(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.Unlock(ctx, "", "pw"); err == nil {
		t.Error("expected an error for an empty key id")
	}
	if err := client.Unlock(ctx, "some-id", ""); err == nil {
		t.Error("expected an error for an empty passphrase")
	}
}

func TestUnlockUnknownKey(t *testing.T) {
	client := newTestClient(t)
	if err := client.Unlock(context.Background(), "no-such-key", "pw"); err == nil {
		t.Fatal("expected an error for an unknown key id")
	}
}

func TestDefaultSessionTTLIsPositive(t *testing.T) {
	if cipher.DefaultSessionTTL <= 0 {
		t.Fatalf("DefaultSessionTTL = %v, want a positive duration", cipher.DefaultSessionTTL)
	}
}
