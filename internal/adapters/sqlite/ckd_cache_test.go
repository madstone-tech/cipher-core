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

	retrieved, err := cache.Get(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Failed to get cache entry: %v", err)
	}

	if retrieved.Email != entry.Email {
		t.Errorf("Expected email %s, got %s", entry.Email, retrieved.Email)
	}
	if retrieved.Fingerprint != entry.Fingerprint {
		t.Errorf("Expected fingerprint %s, got %s", entry.Fingerprint, retrieved.Fingerprint)
	}

	// Test Delete
	if err := cache.Delete(ctx, "alice@example.com"); err != nil {
		t.Fatalf("Failed to delete cache entry: %v", err)
	}

	_, err = cache.Get(ctx, "alice@example.com")
	if err == nil {
		t.Error("Expected error when getting deleted entry, got nil")
	}
}
