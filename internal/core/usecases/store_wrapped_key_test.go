package usecases

import (
	"context"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// validStoreReq returns a minimal valid StoreWrappedKeyRequest for testing.
// PublicKey is 32 bytes, WrappedPrivateKey is 28 bytes (nonce+tag minimum),
// Argon2idSalt is 16 bytes — all pass validation.
func validStoreReq() *StoreWrappedKeyRequest {
	return &StoreWrappedKeyRequest{
		Alias:             "recovery-key",
		Type:              entities.KeyTypeX25519,
		PublicKey:         make([]byte, 32),
		WrappedPrivateKey: make([]byte, 28),
		Argon2idSalt:      make([]byte, 16),
	}
}

// TestStoreWrappedKey_HappyPath verifies that a brand-new key is created via
// Create with no Update calls.
func TestStoreWrappedKey_HappyPath(t *testing.T) {
	repo := &fakeKeyRepo{}
	uc := NewStoreWrappedKey(repo, &fakeLogger{})

	key, err := uc.Execute(context.Background(), validStoreReq())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if key == nil {
		t.Fatal("expected a non-nil key")
	}
	if key.ID == "" {
		t.Error("key.ID must be set")
	}
	if key.Fingerprint == "" {
		t.Error("key.Fingerprint must be set")
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 repo.Create call, got %d", repo.createCalls)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("expected 0 repo.Update calls for brand-new key, got %d", repo.updateCalls)
	}
}

// TestStoreWrappedKey_ReWrap verifies that storing the same public key twice
// with different wrap material updates the existing key rather than creating a
// duplicate. The second call must:
//   - return the key with the NEW WrappedPrivateKey and Argon2idSalt
//   - trigger exactly one Update call
//   - not trigger a second Create call
func TestStoreWrappedKey_ReWrap(t *testing.T) {
	repo := &fakeKeyRepo{}
	uc := NewStoreWrappedKey(repo, &fakeLogger{})

	// First request — uses the zero-byte slices from validStoreReq.
	req1 := validStoreReq()
	key1, err := uc.Execute(context.Background(), req1)
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if key1 == nil {
		t.Fatal("first call: expected non-nil key")
	}

	// Second request — same public key, different wrap material.
	newWrapped := make([]byte, 28)
	for i := range newWrapped {
		newWrapped[i] = 0xFF
	}
	newSalt := make([]byte, 16)
	for i := range newSalt {
		newSalt[i] = 0xAB
	}

	req2 := &StoreWrappedKeyRequest{
		Alias:             "updated-alias",
		Type:              entities.KeyTypeX25519,
		PublicKey:         make([]byte, 32), // same public key as req1
		WrappedPrivateKey: newWrapped,
		Argon2idSalt:      newSalt,
	}

	key2, err := uc.Execute(context.Background(), req2)
	if err != nil {
		t.Fatalf("second Execute (re-wrap): %v", err)
	}
	if key2 == nil {
		t.Fatal("second call: expected non-nil key")
	}

	// IDs must be identical — same public key produces the same deterministic ID.
	if key1.ID != key2.ID {
		t.Errorf("key IDs differ: first=%q second=%q", key1.ID, key2.ID)
	}

	// Returned key must carry the NEW wrap material.
	if string(key2.WrappedPrivateKey) != string(newWrapped) {
		t.Errorf("WrappedPrivateKey not updated: got %v, want %v", key2.WrappedPrivateKey, newWrapped)
	}
	if string(key2.Argon2idSalt) != string(newSalt) {
		t.Errorf("Argon2idSalt not updated: got %v, want %v", key2.Argon2idSalt, newSalt)
	}

	// Verify the repo also reflects the new wrap material.
	stored, err := repo.GetByID(context.Background(), key2.ID)
	if err != nil {
		t.Fatalf("GetByID after re-wrap: %v", err)
	}
	if string(stored.WrappedPrivateKey) != string(newWrapped) {
		t.Error("repo did not persist updated WrappedPrivateKey")
	}
	if string(stored.Argon2idSalt) != string(newSalt) {
		t.Error("repo did not persist updated Argon2idSalt")
	}

	// Create must still have been called exactly once (only the first request).
	if repo.createCalls != 1 {
		t.Fatalf("expected exactly 1 repo.Create call across both executions, got %d", repo.createCalls)
	}
	// Update must have been called exactly once (for the re-wrap).
	if repo.updateCalls != 1 {
		t.Fatalf("expected exactly 1 repo.Update call for re-wrap, got %d", repo.updateCalls)
	}
}

// TestStoreWrappedKey_ReWrap_EmptyAlias verifies that an empty alias on the
// second call does not clobber an existing alias.
func TestStoreWrappedKey_ReWrap_EmptyAlias(t *testing.T) {
	repo := &fakeKeyRepo{}
	uc := NewStoreWrappedKey(repo, &fakeLogger{})

	req1 := validStoreReq() // alias = "recovery-key"
	if _, err := uc.Execute(context.Background(), req1); err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	newWrapped := make([]byte, 28)
	for i := range newWrapped {
		newWrapped[i] = 0x01
	}
	newSalt := make([]byte, 16)
	for i := range newSalt {
		newSalt[i] = 0x02
	}

	req2 := &StoreWrappedKeyRequest{
		Alias:             "", // empty — must not overwrite the existing alias
		Type:              entities.KeyTypeX25519,
		PublicKey:         make([]byte, 32),
		WrappedPrivateKey: newWrapped,
		Argon2idSalt:      newSalt,
	}
	key2, err := uc.Execute(context.Background(), req2)
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}

	if key2.Alias != "recovery-key" {
		t.Errorf("alias was clobbered: got %q, want %q", key2.Alias, "recovery-key")
	}
}

// TestStoreWrappedKey_ValidationErrors verifies that invalid inputs are rejected
// before any repository interaction.
func TestStoreWrappedKey_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		req  *StoreWrappedKeyRequest
	}{
		{
			name: "wrong key type",
			req: &StoreWrappedKeyRequest{
				Type:              "rsa",
				PublicKey:         make([]byte, 32),
				WrappedPrivateKey: make([]byte, 28),
				Argon2idSalt:      make([]byte, 16),
			},
		},
		{
			name: "public key wrong length",
			req: &StoreWrappedKeyRequest{
				Type:              entities.KeyTypeX25519,
				PublicKey:         make([]byte, 31),
				WrappedPrivateKey: make([]byte, 28),
				Argon2idSalt:      make([]byte, 16),
			},
		},
		{
			name: "wrapped private key too short",
			req: &StoreWrappedKeyRequest{
				Type:              entities.KeyTypeX25519,
				PublicKey:         make([]byte, 32),
				WrappedPrivateKey: make([]byte, 27),
				Argon2idSalt:      make([]byte, 16),
			},
		},
		{
			name: "salt wrong length",
			req: &StoreWrappedKeyRequest{
				Type:              entities.KeyTypeX25519,
				PublicKey:         make([]byte, 32),
				WrappedPrivateKey: make([]byte, 28),
				Argon2idSalt:      make([]byte, 15),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeKeyRepo{}
			uc := NewStoreWrappedKey(repo, &fakeLogger{})
			_, err := uc.Execute(context.Background(), tc.req)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if repo.createCalls != 0 {
				t.Errorf("Create must not be called on validation failure, got %d calls", repo.createCalls)
			}
		})
	}
}
