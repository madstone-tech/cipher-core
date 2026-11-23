package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
	_ "modernc.org/sqlite"
)

// openRawDB opens a raw SQLite connection to the given path for test setup.
func openRawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("openRawDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// createLegacyTable creates the old "keys" table schema used before migration.
func createLegacyTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			alias TEXT,
			fingerprint TEXT NOT NULL UNIQUE,
			public_key BLOB,
			private_key BLOB,
			created_at INTEGER NOT NULL,
			expires_at INTEGER,
			usage_count INTEGER DEFAULT 0,
			is_default INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("createLegacyTable: %v", err)
	}
}

// sampleKey returns a valid IdentityKey for use in tests.
func sampleKey(id, fingerprint string, isDefault bool) *entities.IdentityKey {
	return &entities.IdentityKey{
		ID:                id,
		Type:              entities.KeyTypeX25519,
		Fingerprint:       fingerprint,
		PublicKey:         []byte("public-key-bytes-" + id),
		WrappedPrivateKey: []byte("wrapped-private-key-bytes-" + id),
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
		CreatedAt:         time.Now().Truncate(time.Second),
		IsDefault:         isDefault,
	}
}

// TestNewIdentityKeyRepository_FreshDB verifies the identity_keys table is
// created on a fresh database and that basic insert/read works.
func TestNewIdentityKeyRepository_FreshDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")

	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	// Verify table exists via raw query.
	var count int
	err = repo.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='identity_keys'",
	).Scan(&count)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected identity_keys table to exist, got count=%d", count)
	}

	// Insert and read back a key to confirm the table is functional.
	ctx := context.Background()
	key := sampleKey("id-fresh-1", "fp-fresh-1", true)

	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, key.ID)
	}
	if got.Fingerprint != key.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %q, want %q", got.Fingerprint, key.Fingerprint)
	}
}

// TestIdentityKeyRepository_LegacyMigration verifies that rows from the old
// "keys" table are migrated into "identity_keys" and the old table is dropped.
func TestIdentityKeyRepository_LegacyMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// Manually create the legacy table and insert two rows.
	rawDB := openRawDB(t, dbPath)
	createLegacyTable(t, rawDB)

	_, err := rawDB.Exec(`
		INSERT INTO keys (id, type, alias, fingerprint, public_key, private_key, created_at, is_default)
		VALUES
			('leg-1', 'x25519', 'alice', 'fp-leg-1', X'AABB', X'CCDD', 1700000000, 1),
			('leg-2', 'x25519', 'bob',   'fp-leg-2', X'EEFF', X'0011', 1700000001, 0)
	`)
	if err != nil {
		t.Fatalf("insert legacy rows: %v", err)
	}
	_ = rawDB.Close()

	// Now open through the repository — migration should happen.
	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()

	// Both rows must appear in identity_keys.
	keys, err := repo.List(ctx, usecases.KeyFilters{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 migrated keys, got %d", len(keys))
	}

	byID := make(map[string]*entities.IdentityKey, len(keys))
	for _, k := range keys {
		byID[k.ID] = k
	}

	// Verify storage_mode, wrapped_private_key, and argon2id_salt for each row.
	for _, tc := range []struct {
		id          string
		wantPrivKey []byte
	}{
		{"leg-1", []byte{0xCC, 0xDD}},
		{"leg-2", []byte{0x00, 0x11}},
	} {
		k, ok := byID[tc.id]
		if !ok {
			t.Errorf("migrated key %q not found", tc.id)
			continue
		}
		if k.StorageMode != entities.StorageModeStandard {
			t.Errorf("[%s] StorageMode: got %q, want %q", tc.id, k.StorageMode, entities.StorageModeStandard)
		}
		if !bytes.Equal(k.WrappedPrivateKey, tc.wantPrivKey) {
			t.Errorf("[%s] WrappedPrivateKey: got %x, want %x", tc.id, k.WrappedPrivateKey, tc.wantPrivKey)
		}
		if k.Argon2idSalt != nil {
			t.Errorf("[%s] Argon2idSalt: expected nil, got %x", tc.id, k.Argon2idSalt)
		}
	}

	// The old "keys" table must be gone.
	var tableCount int
	err = repo.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys'",
	).Scan(&tableCount)
	if err != nil {
		t.Fatalf("check keys table: %v", err)
	}
	if tableCount != 0 {
		t.Error("expected legacy 'keys' table to be dropped after migration")
	}
}

// TestIdentityKeyRepository_LegacyMigration_SkipsNullPublicKey verifies that
// rows with a NULL public_key are skipped during migration.
func TestIdentityKeyRepository_LegacyMigration_SkipsNullPublicKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_null.db")

	rawDB := openRawDB(t, dbPath)
	createLegacyTable(t, rawDB)

	_, err := rawDB.Exec(`
		INSERT INTO keys (id, type, alias, fingerprint, public_key, private_key, created_at)
		VALUES
			('valid-1', 'x25519', 'alice', 'fp-valid-1', X'AABB', X'CCDD', 1700000000),
			('null-pk', 'x25519', 'bob',   'fp-null-pk', NULL,    X'EEFF', 1700000001)
	`)
	if err != nil {
		t.Fatalf("insert legacy rows: %v", err)
	}
	_ = rawDB.Close()

	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()
	keys, err := repo.List(ctx, usecases.KeyFilters{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 migrated key (skipping null public_key), got %d", len(keys))
	}
	if keys[0].ID != "valid-1" {
		t.Errorf("expected migrated key ID 'valid-1', got %q", keys[0].ID)
	}
}

// TestIdentityKeyRepository_SkipsMigrationWhenNewTableExists verifies that if
// both "keys" and "identity_keys" tables exist, the legacy table is NOT dropped.
func TestIdentityKeyRepository_SkipsMigrationWhenNewTableExists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "both_tables.db")

	rawDB := openRawDB(t, dbPath)
	createLegacyTable(t, rawDB)

	// Create the new identity_keys table manually to simulate an already-migrated DB.
	_, err := rawDB.Exec(`
		CREATE TABLE IF NOT EXISTS identity_keys (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			alias TEXT,
			fingerprint TEXT NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			wrapped_private_key BLOB,
			argon2id_salt BLOB,
			local_wrapped_key BLOB,
			local_salt BLOB,
			storage_mode TEXT NOT NULL DEFAULT 'standard',
			storage_backend TEXT NOT NULL DEFAULT 'sqlite',
			created_at INTEGER NOT NULL,
			expires_at INTEGER,
			usage_count INTEGER DEFAULT 0,
			is_default INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatalf("create identity_keys: %v", err)
	}
	_ = rawDB.Close()

	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	// The legacy "keys" table must still exist — migration was skipped.
	var tableCount int
	err = repo.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys'",
	).Scan(&tableCount)
	if err != nil {
		t.Fatalf("check keys table: %v", err)
	}
	if tableCount != 1 {
		t.Error("expected legacy 'keys' table to still exist when migration is skipped")
	}
}

// TestIdentityKeyRepository_CRUD exercises Create, GetByID, GetByFingerprint,
// GetDefault, List, Update, Delete, and Count.
func TestIdentityKeyRepository_CRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "crud.db")
	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()

	// Count on empty DB.
	n, err := repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count (empty): %v", err)
	}
	if n != 0 {
		t.Errorf("Count (empty): got %d, want 0", n)
	}

	// Create two keys.
	key1 := sampleKey("crud-1", "fp-crud-1", true)
	key2 := sampleKey("crud-2", "fp-crud-2", false)

	if err := repo.Create(ctx, key1); err != nil {
		t.Fatalf("Create key1: %v", err)
	}
	if err := repo.Create(ctx, key2); err != nil {
		t.Fatalf("Create key2: %v", err)
	}

	// Count should be 2.
	n, err = repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Errorf("Count: got %d, want 2", n)
	}

	// GetByID.
	got, err := repo.GetByID(ctx, key1.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != key1.ID {
		t.Errorf("GetByID: got ID %q, want %q", got.ID, key1.ID)
	}
	if !bytes.Equal(got.PublicKey, key1.PublicKey) {
		t.Errorf("GetByID: PublicKey mismatch")
	}
	if !bytes.Equal(got.WrappedPrivateKey, key1.WrappedPrivateKey) {
		t.Errorf("GetByID: WrappedPrivateKey mismatch")
	}
	if got.StorageMode != entities.StorageModeStandard {
		t.Errorf("GetByID: StorageMode got %q, want %q", got.StorageMode, entities.StorageModeStandard)
	}
	if got.StorageBackend != entities.StorageBackendSQLite {
		t.Errorf("GetByID: StorageBackend got %q, want %q", got.StorageBackend, entities.StorageBackendSQLite)
	}
	if got.CreatedAt.Unix() != key1.CreatedAt.Unix() {
		t.Errorf("GetByID: CreatedAt mismatch: got %v, want %v", got.CreatedAt, key1.CreatedAt)
	}

	// GetByID on missing ID returns ErrNotFound.
	_, err = repo.GetByID(ctx, "nonexistent")
	if err != entities.ErrNotFound {
		t.Errorf("GetByID missing: got %v, want ErrNotFound", err)
	}

	// GetByFingerprint.
	got, err = repo.GetByFingerprint(ctx, key2.Fingerprint)
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if got.ID != key2.ID {
		t.Errorf("GetByFingerprint: got ID %q, want %q", got.ID, key2.ID)
	}

	// GetByFingerprint on missing fingerprint returns ErrNotFound.
	_, err = repo.GetByFingerprint(ctx, "no-such-fp")
	if err != entities.ErrNotFound {
		t.Errorf("GetByFingerprint missing: got %v, want ErrNotFound", err)
	}

	// GetDefault returns key1 (is_default = true).
	def, err := repo.GetDefault(ctx)
	if err != nil {
		t.Fatalf("GetDefault: %v", err)
	}
	if def.ID != key1.ID {
		t.Errorf("GetDefault: got %q, want %q", def.ID, key1.ID)
	}

	// List all.
	all, err := repo.List(ctx, usecases.KeyFilters{})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List all: got %d, want 2", len(all))
	}

	// List with Limit.
	limited, err := repo.List(ctx, usecases.KeyFilters{Limit: 1})
	if err != nil {
		t.Fatalf("List limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("List limit=1: got %d, want 1", len(limited))
	}

	// List filter by IsDefault=true.
	isDefault := true
	defaults, err := repo.List(ctx, usecases.KeyFilters{IsDefault: &isDefault})
	if err != nil {
		t.Fatalf("List IsDefault: %v", err)
	}
	if len(defaults) != 1 || defaults[0].ID != key1.ID {
		t.Errorf("List IsDefault: unexpected result: %+v", defaults)
	}

	// Update key2: flip IsDefault, change Alias.
	key2.IsDefault = true
	key2.Alias = "updated-alias"
	if err := repo.Update(ctx, key2); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated, err := repo.GetByID(ctx, key2.ID)
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if updated.Alias != "updated-alias" {
		t.Errorf("Update Alias: got %q, want %q", updated.Alias, "updated-alias")
	}
	if !updated.IsDefault {
		t.Error("Update IsDefault: expected true")
	}

	// Delete key1.
	if err := repo.Delete(ctx, key1.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = repo.GetByID(ctx, key1.ID)
	if err != entities.ErrNotFound {
		t.Errorf("GetByID after Delete: got %v, want ErrNotFound", err)
	}

	// Count should now be 1.
	n, err = repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count after delete: %v", err)
	}
	if n != 1 {
		t.Errorf("Count after delete: got %d, want 1", n)
	}

	// GetDefault should now return ErrNotFound if key1 (the original default) was
	// deleted and key2 was updated to be default.
	def, err = repo.GetDefault(ctx)
	if err != nil {
		t.Fatalf("GetDefault after delete: %v", err)
	}
	if def.ID != key2.ID {
		t.Errorf("GetDefault after delete: got %q, want %q", def.ID, key2.ID)
	}
}

// TestIdentityKeyRepository_ListMetadataContract verifies the blob-free
// projection: ListMetadata returns every metadata field correctly but NEVER
// carries wrapped private-key material (zero-knowledge listing surfaces),
// while List still returns the material for decrypt/backup/export paths.
func TestIdentityKeyRepository_ListMetadataContract(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "metadata.db")
	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()
	key := sampleKey("meta-1", "fp-meta-1", true)
	key.Argon2idSalt = []byte("0123456789abcdef") // decrypt path needs salt round-trip
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	metas, err := repo.ListMetadata(ctx, usecases.KeyFilters{})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("ListMetadata: expected 1 key, got %d", len(metas))
	}
	m := metas[0]

	// Metadata fields present and correct.
	if m.ID != key.ID || m.Type != key.Type || m.Alias != key.Alias {
		t.Errorf("ListMetadata core fields mismatch: got %+v", m)
	}
	if m.Fingerprint != key.Fingerprint {
		t.Errorf("Fingerprint: got %q, want %q", m.Fingerprint, key.Fingerprint)
	}
	if !bytes.Equal(m.PublicKey, key.PublicKey) {
		t.Errorf("PublicKey mismatch (public key IS part of metadata)")
	}
	if m.StorageMode != key.StorageMode {
		t.Errorf("StorageMode: got %q, want %q", m.StorageMode, key.StorageMode)
	}
	if !m.IsDefault {
		t.Errorf("IsDefault: got false, want true")
	}

	// Material must be absent: KeyMetadata has NO wrapped-key fields at all
	// (compile-time enforced — the type cannot carry material).
	var _ *entities.KeyMetadata = m

	// The full-material path still returns the blobs (decrypt/backup rely on it).
	full, err := repo.List(ctx, usecases.KeyFilters{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(full) != 1 || !bytes.Equal(full[0].WrappedPrivateKey, key.WrappedPrivateKey) {
		t.Fatalf("List must still return WrappedPrivateKey for decrypt/backup paths")
	}
	if !bytes.Equal(full[0].Argon2idSalt, key.Argon2idSalt) || len(full[0].Argon2idSalt) == 0 {
		t.Errorf("List: Argon2idSalt mismatch")
	}
}

// TestIdentityKeyRepository_ListWithExpiry verifies that ListWithExpiry returns
// only keys with a non-null expires_at, and that keys without expiry are excluded.
func TestIdentityKeyRepository_ListWithExpiry(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "expiry.db")
	repo, err := NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()

	// Key without expiry.
	noExpiry := sampleKey("ke1", "fp-ke1", false)
	if err := repo.Create(ctx, noExpiry); err != nil {
		t.Fatalf("Create noExpiry: %v", err)
	}

	// Key expiring in 7 days.
	exp7d := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	withExpiry := sampleKey("ke2", "fp-ke2", false)
	withExpiry.ExpiresAt = &exp7d
	if err := repo.Create(ctx, withExpiry); err != nil {
		t.Fatalf("Create withExpiry: %v", err)
	}

	// Key already expired.
	expPast := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	alreadyExpired := sampleKey("ke3", "fp-ke3", false)
	alreadyExpired.ExpiresAt = &expPast
	if err := repo.Create(ctx, alreadyExpired); err != nil {
		t.Fatalf("Create alreadyExpired: %v", err)
	}

	keys, err := repo.ListWithExpiry(ctx)
	if err != nil {
		t.Fatalf("ListWithExpiry: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys with expiry, got %d", len(keys))
	}

	ids := map[string]bool{}
	for _, k := range keys {
		ids[k.ID] = true
		if k.ExpiresAt == nil {
			t.Errorf("key %s: ExpiresAt should not be nil", k.ID)
		}
	}
	if !ids["ke2"] {
		t.Error("expected ke2 (expiring in 7d) in ListWithExpiry result")
	}
	if !ids["ke3"] {
		t.Error("expected ke3 (already expired) in ListWithExpiry result")
	}
	if ids["ke1"] {
		t.Error("ke1 (no expiry) should NOT appear in ListWithExpiry result")
	}
}

// TestIdentityKeyRepository_InMemorySharesSchema verifies that a ":memory:"
// database is one database for every repository on the connection: each pool
// connection to ":memory:" would otherwise open its own empty database.
func TestIdentityKeyRepository_InMemorySharesSchema(t *testing.T) {
	repo, err := NewIdentityKeyRepository(":memory:")
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if got := repo.DB().Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d; want 1 for :memory:", got)
	}

	policyRepo, err := NewSharedKeyPolicyRepository(repo.DB())
	if err != nil {
		t.Fatalf("NewSharedKeyPolicyRepository: %v", err)
	}
	cache := NewCKDCacheRepository(repo.DB())

	ctx := context.Background()
	if err := repo.Create(ctx, sampleKey("k1", "fp1", true)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Concurrent use forces extra pool connections when the pool is not
	// limited; each would see an empty database without the schema.
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*3)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := repo.Count(ctx)
			if err != nil {
				errs <- err
				return
			}
			if n != 1 {
				errs <- fmt.Errorf("Count = %d; want 1", n)
			}
			if _, err := policyRepo.ListPolicies(ctx, "owner"); err != nil {
				errs <- err
			}
			if _, err := cache.Get(ctx, "nobody@example.com"); err != nil && err.Error() != "not found" {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("repository on shared :memory: db: %v", err)
	}
}
