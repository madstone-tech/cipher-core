package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// CKDCacheRepository implements the CKDCacheRepository interface
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

// migrate creates the CKD cache table
func (r *CKDCacheRepository) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS ckd_cache (
		email TEXT PRIMARY KEY,
		public_key BLOB NOT NULL,
		fingerprint TEXT NOT NULL,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_ckd_cache_fingerprint ON ckd_cache(fingerprint);
	`

	_, err := r.db.Exec(schema)
	return err
}

// Get retrieves a cached CKD entry
func (r *CKDCacheRepository) Get(ctx context.Context, email string) (*usecases.CKDCacheEntry, error) {
	entry := &usecases.CKDCacheEntry{}

	err := r.db.QueryRowContext(ctx, `
		SELECT email, public_key, fingerprint, first_seen, last_seen
		FROM ckd_cache WHERE email = ?
	`, email).Scan(&entry.Email, &entry.PublicKey, &entry.Fingerprint, &entry.FirstSeen, &entry.LastSeen)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}

	return entry, nil
}

// Set stores or updates a CKD cache entry
func (r *CKDCacheRepository) Set(ctx context.Context, entry *usecases.CKDCacheEntry) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ckd_cache (email, public_key, fingerprint, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			public_key = excluded.public_key,
			fingerprint = excluded.fingerprint,
			last_seen = excluded.last_seen
	`, entry.Email, entry.PublicKey, entry.Fingerprint, entry.FirstSeen, entry.LastSeen)
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}

	return nil
}

// Delete removes a CKD cache entry
func (r *CKDCacheRepository) Delete(ctx context.Context, email string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM ckd_cache WHERE email = ?", email)
	if err != nil {
		return fmt.Errorf("failed to delete cache entry: %w", err)
	}
	return nil
}
