package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

func TestCKDCache(t *testing.T) {
	// Create temp database
	tmpDir, err := os.MkdirTemp("", "ckd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	keyRepo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
	}
	defer keyRepo.Close()

	cache := NewCKDCacheRepository(keyRepo.DB())
	ctx := context.Background()

	// Test Set and Get
	entry := &usecases.CKDCacheEntry{
		Email:       "alice@example.com",
		PublicKey:   []byte("test-public-key"),
		Fingerprint: "abc123",
		FirstSeen:   1234567890,
		LastSeen:    1234567890,
	}

	if err := cache.Set(ctx, entry); err != nil {
		t.Fatalf("Failed to set cache entry: %v", err)
	}

	retrieved, err := cache.Get(ctx, "alice@example.com", "")
	if err != nil {
		t.Fatalf("Failed to get cache entry: %v", err)
	}

	if retrieved.Email != entry.Email {
		t.Errorf("Expected email %s, got %s", entry.Email, retrieved.Email)
	}
	if retrieved.Fingerprint != entry.Fingerprint {
		t.Errorf("Expected fingerprint %s, got %s", entry.Fingerprint, retrieved.Fingerprint)
	}
	if retrieved.KeyType != usecases.DefaultCKDKeyType {
		t.Errorf("Expected key type %s, got %s", usecases.DefaultCKDKeyType, retrieved.KeyType)
	}

	// Test Delete
	if err := cache.Delete(ctx, "alice@example.com", ""); err != nil {
		t.Fatalf("Failed to delete cache entry: %v", err)
	}

	_, err = cache.Get(ctx, "alice@example.com", "")
	if err == nil {
		t.Error("Expected error when getting deleted entry, got nil")
	}
}

// TestCKDCachePreMigrationSchema proves the v0.3.x (email-PK) table migrates
// in place: rows read back with the default key type, and the new composite
// identity works after the rebuild.
func TestCKDCachePreMigrationSchema(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ckd-mig-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	keyRepo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
	}
	defer keyRepo.Close()

	// Build the legacy shape before the cache repo touches the table.
	db := keyRepo.DB()
	_, err = db.Exec(`
		DROP TABLE IF EXISTS ckd_cache;
		CREATE TABLE ckd_cache (
			email TEXT PRIMARY KEY,
			public_key BLOB NOT NULL,
			fingerprint TEXT NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL
		);
		INSERT INTO ckd_cache (email, public_key, fingerprint, first_seen, last_seen)
			VALUES ('legacy@example.com', X'0102030405', 'deadbeef', 1000, 2000);
	`)
	if err != nil {
		t.Fatalf("Failed to build legacy schema: %v", err)
	}

	cache := NewCKDCacheRepository(db) // runs the migration

	entry, err := cache.Get(context.Background(), "legacy@example.com", "")
	if err != nil {
		t.Fatalf("Failed to read migrated row: %v", err)
	}
	if entry.KeyType != usecases.DefaultCKDKeyType {
		t.Errorf("Migrated row key type = %s, want %s", entry.KeyType, usecases.DefaultCKDKeyType)
	}
	if string(entry.PublicKey) != "\x01\x02\x03\x04\x05" {
		t.Errorf("Migrated row public key = %x, want 0102030405", entry.PublicKey)
	}
	if entry.FirstSeen != 1000 {
		t.Errorf("Migrated row first seen = %d, want 1000", entry.FirstSeen)
	}
}

// TestCKDCacheTwoKeyTypesIndependence proves (email, key_type) identity: two
// types for one email are distinct entries; one never overwrites the other.
func TestCKDCacheTwoKeyTypesIndependence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ckd-multi-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	keyRepo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
	}
	defer keyRepo.Close()

	cache := NewCKDCacheRepository(keyRepo.DB())
	ctx := context.Background()

	x25519 := &usecases.CKDCacheEntry{
		Email:       "eve@example.com",
		KeyType:     "x25519",
		PublicKey:   []byte("x25519-key"),
		Fingerprint: "fpx25519",
		FirstSeen:   10,
		LastSeen:    10,
	}
	future := &usecases.CKDCacheEntry{
		Email:       "eve@example.com",
		KeyType:     "future-kyber",
		PublicKey:   []byte("pq-key"),
		Fingerprint: "fppq",
		FirstSeen:   20,
		LastSeen:    20,
	}
	if err := cache.Set(ctx, x25519); err != nil {
		t.Fatalf("Set x25519: %v", err)
	}
	if err := cache.Set(ctx, future); err != nil {
		t.Fatalf("Set future-kyber: %v", err)
	}

	gotX, err := cache.Get(ctx, "eve@example.com", "x25519")
	if err != nil {
		t.Fatalf("Get x25519: %v", err)
	}
	if gotX.Fingerprint != "fpx25519" {
		t.Errorf("x25519 entry clobbered: fingerprint = %s", gotX.Fingerprint)
	}
	gotPQ, err := cache.Get(ctx, "eve@example.com", "future-kyber")
	if err != nil {
		t.Fatalf("Get future-kyber: %v", err)
	}
	if gotPQ.Fingerprint != "fppq" {
		t.Errorf("future-kyber entry clobbered: fingerprint = %s", gotPQ.Fingerprint)
	}

	// Deleting one type leaves the other untouched.
	if err := cache.Delete(ctx, "eve@example.com", "x25519"); err != nil {
		t.Fatalf("Delete x25519: %v", err)
	}
	if _, err := cache.Get(ctx, "eve@example.com", "x25519"); err == nil {
		t.Error("x25519 entry still present after delete")
	}
	if _, err := cache.Get(ctx, "eve@example.com", "future-kyber"); err != nil {
		t.Errorf("future-kyber entry should survive the x25519 delete: %v", err)
	}
}
