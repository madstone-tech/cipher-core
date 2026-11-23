package entities

import (
	"testing"
	"time"
)

func TestIdentityKey_Validate_StandardMode(t *testing.T) {
	base := IdentityKey{
		ID:                "key-1",
		Type:              KeyTypeX25519,
		Fingerprint:       "abc123",
		PublicKey:         []byte("pubkey"),
		WrappedPrivateKey: []byte("wrapped"),
		Argon2idSalt:      []byte("0123456789abcdef"),
		StorageMode:       StorageModeStandard,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("valid standard key should pass: %v", err)
	}
}

func TestIdentityKey_Validate_StandardModeTransitional(t *testing.T) {
	// Migrated keys have WrappedPrivateKey but no salt yet (transitional)
	key := IdentityKey{
		ID:                "key-2",
		Type:              KeyTypeX25519,
		Fingerprint:       "abc123",
		PublicKey:         []byte("pubkey"),
		WrappedPrivateKey: []byte("raw-bytes-not-yet-wrapped"),
		Argon2idSalt:      nil, // transitional — allowed
		StorageMode:       StorageModeStandard,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := key.Validate(); err != nil {
		t.Fatalf("transitional standard key (nil salt) should pass: %v", err)
	}
}

func TestIdentityKey_Validate_StandardModeMissingWrappedKey(t *testing.T) {
	key := IdentityKey{
		ID:             "key-3",
		Type:           KeyTypeX25519,
		Fingerprint:    "abc123",
		PublicKey:      []byte("pubkey"),
		StorageMode:    StorageModeStandard,
		StorageBackend: StorageBackendSQLite,
		CreatedAt:      time.Now(),
	}

	if err := key.Validate(); err == nil {
		t.Fatal("standard mode without WrappedPrivateKey should fail")
	}
}

func TestIdentityKey_Validate_AdvancedMode(t *testing.T) {
	key := IdentityKey{
		ID:             "key-4",
		Type:           KeyTypeX25519,
		Fingerprint:    "abc123",
		PublicKey:      []byte("pubkey"),
		StorageMode:    StorageModeAdvanced,
		StorageBackend: StorageBackendSQLite,
		CreatedAt:      time.Now(),
	}

	if err := key.Validate(); err != nil {
		t.Fatalf("valid advanced key should pass: %v", err)
	}
}

func TestIdentityKey_Validate_AdvancedModeWithWrappedKey(t *testing.T) {
	key := IdentityKey{
		ID:                "key-5",
		Type:              KeyTypeX25519,
		Fingerprint:       "abc123",
		PublicKey:         []byte("pubkey"),
		WrappedPrivateKey: []byte("should-not-be-here"),
		StorageMode:       StorageModeAdvanced,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := key.Validate(); err == nil {
		t.Fatal("advanced mode with WrappedPrivateKey should fail")
	}
}

func TestIdentityKey_Validate_MissingPublicKey(t *testing.T) {
	key := IdentityKey{
		ID:                "key-6",
		Type:              KeyTypeX25519,
		Fingerprint:       "abc123",
		WrappedPrivateKey: []byte("wrapped"),
		StorageMode:       StorageModeStandard,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := key.Validate(); err == nil {
		t.Fatal("missing PublicKey should fail")
	}
}

func TestIdentityKey_Validate_MissingFingerprint(t *testing.T) {
	key := IdentityKey{
		ID:                "key-7",
		Type:              KeyTypeX25519,
		PublicKey:         []byte("pubkey"),
		WrappedPrivateKey: []byte("wrapped"),
		StorageMode:       StorageModeStandard,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := key.Validate(); err == nil {
		t.Fatal("missing Fingerprint should fail")
	}
}

func TestIdentityKey_Validate_InvalidKeyType(t *testing.T) {
	key := IdentityKey{
		ID:                "key-8",
		Type:              "aes256", // removed type
		Fingerprint:       "abc123",
		PublicKey:         []byte("pubkey"),
		WrappedPrivateKey: []byte("wrapped"),
		StorageMode:       StorageModeStandard,
		StorageBackend:    StorageBackendSQLite,
		CreatedAt:         time.Now(),
	}

	if err := key.Validate(); err == nil {
		t.Fatal("invalid key type should fail")
	}
}

func TestIdentityKey_IsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	expired := IdentityKey{ExpiresAt: &past}
	if !expired.IsExpired() {
		t.Error("key with past expiry should be expired")
	}

	notExpired := IdentityKey{ExpiresAt: &future}
	if notExpired.IsExpired() {
		t.Error("key with future expiry should not be expired")
	}

	noExpiry := IdentityKey{}
	if noExpiry.IsExpired() {
		t.Error("key with no expiry should not be expired")
	}
}

func TestIdentityKey_IncrementUsage(t *testing.T) {
	key := IdentityKey{UsageCount: 5}
	key.IncrementUsage()
	if key.UsageCount != 6 {
		t.Errorf("UsageCount = %d, want 6", key.UsageCount)
	}
}
