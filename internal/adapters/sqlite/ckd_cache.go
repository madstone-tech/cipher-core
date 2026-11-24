package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// CKDCacheRepository implements the CKDCacheRepository interface.
// Entries are keyed by (email, key_type); KeyType "" reads as the default
// type (x25519).
type CKDCacheRepository struct {
	db *sql.DB
}

// NewCKDCacheRepository creates a new CKD cache repository
func NewCKDCacheRepository(db *sql.DB) *CKDCacheRepository {
	repo := &CKDCacheRepository{db: db}
	if err := repo.migrate(); err != nil {
		slog.Warn("ckd_cache migration failed; CKD cache may be unavailable", "error", err)
	}
	return repo
}

// migrate creates the CKD cache table and migrates a pre-key_type (v0.3.x)
// table in place. The migration is additive: create the new shape, copy with
// the default type, swap. On failure callers keep working cacheless (the
// lookup path treats every cache error as a miss).
func (r *CKDCacheRepository) migrate() error {
	if err := r.migrateAddKeyType(); err != nil {
		return fmt.Errorf("key_type migration: %w", err)
	}
	schema := `
	ALTER TABLE ckd_cache ADD COLUMN key_type TEXT NOT NULL DEFAULT '` + usecases.DefaultCKDKeyType + `';
	`
	// The ALTER is a no-op when the column already exists (fresh table).
	if _, err := r.db.Exec(schema); err != nil {
		if !columnExists(r.db, "ckd_cache", "key_type") {
			return err
		}
	}

	index := `
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ckd_cache_email_keytype
		ON ckd_cache(email, key_type);
	CREATE INDEX IF NOT EXISTS idx_ckd_cache_fingerprint ON ckd_cache(fingerprint);
	`
	_, err := r.db.Exec(index)
	return err
}

// migrateAddKeyType rebuilds a legacy (email-PK) table into the composite
// (email, key_type) form, deduping rows on conflict and keeping the lowest
// first_seen. A table already in the new shape passes through untouched.
func (r *CKDCacheRepository) migrateAddKeyType() error {
	tables, err := r.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name='ckd_cache'`)
	if err != nil {
		return err
	}
	tableExists := tables.Next()
	closeErr := tables.Close()
	if closeErr != nil {
		return closeErr
	}
	if !tableExists || columnExists(r.db, "ckd_cache", "key_type") {
		ensureFresh := `
		CREATE TABLE IF NOT EXISTS ckd_cache (
			email TEXT NOT NULL,
			key_type TEXT NOT NULL DEFAULT '` + usecases.DefaultCKDKeyType + `',
			public_key BLOB NOT NULL,
			fingerprint TEXT NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			PRIMARY KEY (email, key_type)
		);
		`
		_, err := r.db.Exec(ensureFresh)
		return err
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // best-effort: commit-or-rollback below

	steps := []string{
		`CREATE TABLE ckd_cache_new (
			email TEXT NOT NULL,
			key_type TEXT NOT NULL DEFAULT '` + usecases.DefaultCKDKeyType + `',
			public_key BLOB NOT NULL,
			fingerprint TEXT NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			PRIMARY KEY (email, key_type)
		);`,
		`INSERT INTO ckd_cache_new (email, key_type, public_key, fingerprint, first_seen, last_seen)
			SELECT email, '` + usecases.DefaultCKDKeyType + `', public_key, fingerprint, first_seen, last_seen
			FROM ckd_cache
			WHERE true
			ON CONFLICT(email, key_type) DO UPDATE SET
				first_seen = min(ckd_cache_new.first_seen, excluded.first_seen);`,
		`DROP TABLE ckd_cache;`,
		`ALTER TABLE ckd_cache_new RENAME TO ckd_cache;`,
	}
	for _, step := range steps {
		if _, err := tx.Exec(step); err != nil {
			return fmt.Errorf("ckd_cache rebuild: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ckd_cache rebuild commit: %w", err)
	}
	return nil
}

// columnExists reports whether table.column is present (used to make the
// ALTER idempotent on a fresh or already-migrated table).
func columnExists(db *sql.DB, table, column string) bool {
	rows, err := db.Query(fmt.Sprintf(
		`SELECT 1 FROM pragma_table_info(%q) WHERE name = ?`, table), column)
	if err != nil {
		return false
	}
	has := rows.Next()
	closeErr := rows.Close()
	if closeErr != nil {
		return false
	}
	return has
}

// Get retrieves a cached CKD entry by (email, key type). keyType "" reads as
// the default type.
func (r *CKDCacheRepository) Get(ctx context.Context, email, keyType string) (*usecases.CKDCacheEntry, error) {
	if keyType == "" {
		keyType = usecases.DefaultCKDKeyType
	}
	entry := &usecases.CKDCacheEntry{}

	err := r.db.QueryRowContext(ctx, `
		SELECT email, key_type, public_key, fingerprint, first_seen, last_seen
		FROM ckd_cache WHERE email = ? AND key_type = ?
	`, email, keyType).Scan(&entry.Email, &entry.KeyType, &entry.PublicKey, &entry.Fingerprint, &entry.FirstSeen, &entry.LastSeen)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}

	return entry, nil
}

// Set stores or updates a CKD cache entry under (email, key type). keyType ""
// stores as the default type.
func (r *CKDCacheRepository) Set(ctx context.Context, entry *usecases.CKDCacheEntry) error {
	keyType := entry.KeyType
	if keyType == "" {
		keyType = usecases.DefaultCKDKeyType
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ckd_cache (email, key_type, public_key, fingerprint, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(email, key_type) DO UPDATE SET
			public_key = excluded.public_key,
			fingerprint = excluded.fingerprint,
			last_seen = excluded.last_seen
	`, entry.Email, keyType, entry.PublicKey, entry.Fingerprint, entry.FirstSeen, entry.LastSeen)
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}

	return nil
}

// Delete removes a CKD cache entry by (email, key type). keyType "" removes
// the default type only — distinct types are independent entries.
func (r *CKDCacheRepository) Delete(ctx context.Context, email, keyType string) error {
	if keyType == "" {
		keyType = usecases.DefaultCKDKeyType
	}
	_, err := r.db.ExecContext(ctx, "DELETE FROM ckd_cache WHERE email = ? AND key_type = ?", email, keyType)
	if err != nil {
		return fmt.Errorf("failed to delete cache entry: %w", err)
	}
	return nil
}
