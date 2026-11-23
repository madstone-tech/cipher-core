package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// RecoveryKeyRepository implements usecases.RecoveryKeyRepository using SQLite.
type RecoveryKeyRepository struct {
	db *sql.DB
}

// NewRecoveryKeyRepository creates a RecoveryKeyRepository using an existing *sql.DB.
func NewRecoveryKeyRepository(db *sql.DB) *RecoveryKeyRepository {
	repo := &RecoveryKeyRepository{db: db}
	if err := repo.migrate(); err != nil {
		slog.Warn("recovery_keys migration failed; recovery keys may be unavailable", "error", err)
	}
	return repo
}

func (r *RecoveryKeyRepository) migrate() error {
	_, err := r.db.Exec(`
		CREATE TABLE IF NOT EXISTS recovery_keys (
			id         TEXT    PRIMARY KEY,
			salt       BLOB    NOT NULL,
			created_at INTEGER NOT NULL
		);
	`)
	return err
}

// Create persists a RecoveryKey.
func (r *RecoveryKeyRepository) Create(ctx context.Context, rk *entities.RecoveryKey) error {
	if err := rk.Validate(); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO recovery_keys (id, salt, created_at) VALUES (?, ?, ?)`,
		rk.ID, rk.Salt, rk.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to create recovery key: %w", err)
	}
	return nil
}

// Get returns the first (and only) recovery key, or ErrNotFound if the table is empty.
func (r *RecoveryKeyRepository) Get(ctx context.Context) (*entities.RecoveryKey, error) {
	rk := &entities.RecoveryKey{}
	var createdAt int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id, salt, created_at FROM recovery_keys LIMIT 1`,
	).Scan(&rk.ID, &rk.Salt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, entities.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key: %w", err)
	}
	rk.CreatedAt = time.Unix(createdAt, 0)
	return rk, nil
}

// Count returns the number of recovery keys stored.
func (r *RecoveryKeyRepository) Count(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_keys`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count recovery keys: %w", err)
	}
	return n, nil
}
