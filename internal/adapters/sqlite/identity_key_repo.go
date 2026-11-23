package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
	_ "modernc.org/sqlite"
)

// IdentityKeyRepository implements the IdentityKeyRepository interface using SQLite
type IdentityKeyRepository struct {
	db *sql.DB
}

// InMemoryPath is the SQLite path for a database that lives only in memory.
const InMemoryPath = ":memory:"

// NewIdentityKeyRepository creates a new SQLite identity key repository.
// For InMemoryPath the pool holds one connection, because each connection to
// ":memory:" opens its own empty database.
func NewIdentityKeyRepository(dbPath string) (*IdentityKeyRepository, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if dbPath == InMemoryPath {
		db.SetMaxOpenConns(1)
	}

	repo := &IdentityKeyRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to migrate database: %w", err), db.Close())
	}
	if path := usecases.KeyStorePath(dbPath); path != "" {
		// A DSN can carry "file:" and "?_pragma=…" (T-2): chmod the file.
		if err := restrictDBFiles(path); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}
	return repo, nil
}

// restrictDBFiles sets the database file and its SQLite side files to mode
// 0600: the store holds wrapped private keys and their salts, and SQLite
// creates files with the process umask (often 0644).
func restrictDBFiles(dbPath string) error {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("restrict %s to mode 0600: %w", p, err)
		}
	}
	return nil
}

// DB returns the underlying database connection
func (r *IdentityKeyRepository) DB() *sql.DB {
	return r.db
}

// tableExists checks whether a table exists in the database.
func (r *IdentityKeyRepository) tableExists(name string) (bool, error) {
	var count int
	err := r.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// migrate creates the identity_keys table and migrates legacy data if needed.
func (r *IdentityKeyRepository) migrate() error {
	// Check if new table already exists
	hasNew, err := r.tableExists("identity_keys")
	if err != nil {
		return fmt.Errorf("failed to check identity_keys table: %w", err)
	}

	if hasNew {
		// New schema already in place — nothing to do
		return nil
	}

	// Check if legacy keys table exists
	hasLegacy, err := r.tableExists("keys")
	if err != nil {
		return fmt.Errorf("failed to check legacy keys table: %w", err)
	}

	// Create the new identity_keys table
	// NOTE: single-user CLI store. Unlike the Postgres schema — which scopes
	// uniqueness per user via UNIQUE(user_id, fingerprint) and carries a user_id
	// column — this table has no user_id and enforces a GLOBAL `fingerprint UNIQUE`.
	// This divergence is intentional; do not "align" it with Postgres.
	schema := `
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
	);

	CREATE INDEX IF NOT EXISTS idx_identity_keys_fingerprint ON identity_keys(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_identity_keys_is_default ON identity_keys(is_default);
	`

	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create identity_keys table: %w", err)
	}

	// Migrate legacy data if old table exists
	if hasLegacy {
		if err := r.migrateLegacyKeys(); err != nil {
			return fmt.Errorf("failed to migrate legacy keys: %w", err)
		}
	}

	return nil
}

// migrateLegacyKeys copies rows from the legacy keys table into identity_keys.
func (r *IdentityKeyRepository) migrateLegacyKeys() error {
	// Count rows with NULL public_key that cannot be migrated
	var skipped int
	err := r.db.QueryRow("SELECT COUNT(*) FROM keys WHERE public_key IS NULL").Scan(&skipped)
	if err != nil {
		return fmt.Errorf("failed to count unmigrated keys: %w", err)
	}
	if skipped > 0 {
		slog.Warn("Skipping legacy keys with NULL public_key during migration",
			"count", skipped)
	}

	// Copy valid rows into identity_keys
	result, err := r.db.Exec(`
		INSERT INTO identity_keys (id, type, alias, fingerprint, public_key, wrapped_private_key,
			argon2id_salt, storage_mode, storage_backend, created_at, expires_at, usage_count, is_default)
		SELECT id, type, alias, fingerprint, public_key, private_key,
			NULL, 'standard', 'sqlite', created_at, expires_at, usage_count, is_default
		FROM keys
		WHERE public_key IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("failed to copy legacy keys: %w", err)
	}

	migrated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to count migrated legacy keys: %w", err)
	}
	slog.Warn("Migrated keys from legacy format. Keys will be wrapped on next use.",
		"count", migrated)

	// Drop legacy table
	if _, err := r.db.Exec("DROP TABLE keys"); err != nil {
		return fmt.Errorf("failed to drop legacy keys table: %w", err)
	}

	return nil
}

// Create creates a new identity key
func (r *IdentityKeyRepository) Create(ctx context.Context, key *entities.IdentityKey) error {
	if err := key.Validate(); err != nil {
		return err
	}

	var expiresAt *int64
	if key.ExpiresAt != nil {
		ts := key.ExpiresAt.Unix()
		expiresAt = &ts
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO identity_keys (id, type, alias, fingerprint, public_key, wrapped_private_key,
			argon2id_salt, local_wrapped_key, local_salt, storage_mode, storage_backend,
			created_at, expires_at, usage_count, is_default)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, key.ID, key.Type, key.Alias, key.Fingerprint, key.PublicKey, key.WrappedPrivateKey,
		key.Argon2idSalt, key.LocalWrappedKey, key.LocalSalt,
		key.StorageMode, key.StorageBackend,
		key.CreatedAt.Unix(), expiresAt, key.UsageCount, boolToInt(key.IsDefault))
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	return nil
}

// scanIdentityKey scans a row into an IdentityKey struct
func scanIdentityKey(scanner interface {
	Scan(dest ...interface{}) error
},
) (*entities.IdentityKey, error) {
	key := &entities.IdentityKey{}
	var createdAt, expiresAt sql.NullInt64
	var isDefault int
	var storageMode, storageBackend string

	err := scanner.Scan(
		&key.ID, &key.Type, &key.Alias, &key.Fingerprint,
		&key.PublicKey, &key.WrappedPrivateKey, &key.Argon2idSalt,
		&key.LocalWrappedKey, &key.LocalSalt,
		&storageMode, &storageBackend,
		&createdAt, &expiresAt, &key.UsageCount, &isDefault,
	)
	if err != nil {
		return nil, err
	}

	key.StorageMode = entities.StorageMode(storageMode)
	key.StorageBackend = entities.StorageBackend(storageBackend)
	key.CreatedAt = time.Unix(createdAt.Int64, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		key.ExpiresAt = &t
	}
	key.IsDefault = isDefault == 1

	return key, nil
}

const identityKeyCols = `id, type, alias, fingerprint, public_key, wrapped_private_key,
	argon2id_salt, local_wrapped_key, local_salt, storage_mode, storage_backend,
	created_at, expires_at, usage_count, is_default`

// GetByID retrieves an identity key by ID
func (r *IdentityKeyRepository) GetByID(ctx context.Context, id string) (*entities.IdentityKey, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+identityKeyCols+` FROM identity_keys WHERE id = ?`, id)
	key, err := scanIdentityKey(row)
	if err == sql.ErrNoRows {
		return nil, entities.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return key, nil
}

// GetByFingerprint retrieves an identity key by fingerprint
func (r *IdentityKeyRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*entities.IdentityKey, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+identityKeyCols+` FROM identity_keys WHERE fingerprint = ?`, fingerprint)
	key, err := scanIdentityKey(row)
	if err == sql.ErrNoRows {
		return nil, entities.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return key, nil
}

// GetDefault retrieves the default identity key
func (r *IdentityKeyRepository) GetDefault(ctx context.Context) (*entities.IdentityKey, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+identityKeyCols+` FROM identity_keys WHERE is_default = 1 LIMIT 1`)
	key, err := scanIdentityKey(row)
	if err == sql.ErrNoRows {
		return nil, entities.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get default key: %w", err)
	}
	return key, nil
}

// List retrieves identity keys with filters
func (r *IdentityKeyRepository) List(ctx context.Context, filters usecases.KeyFilters) ([]*entities.IdentityKey, error) {
	query := `SELECT ` + identityKeyCols + ` FROM identity_keys WHERE 1=1`
	args := []interface{}{}

	if filters.Type != "" {
		query += " AND type = ?"
		args = append(args, filters.Type)
	}
	if filters.Alias != "" {
		query += " AND alias = ?"
		args = append(args, filters.Alias)
	}
	if filters.IsDefault != nil {
		query += " AND is_default = ?"
		args = append(args, boolToInt(*filters.IsDefault))
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)
	}
	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var keys []*entities.IdentityKey
	for rows.Next() {
		key, err := scanIdentityKey(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// sqliteKeyFilterSQL builds the WHERE/ORDER/LIMIT clause shared by List and
// ListMetadata (?-numbered placeholders).
func sqliteKeyFilterSQL(filters usecases.KeyFilters) (string, []interface{}) {
	query := ""
	args := []interface{}{}

	if filters.Type != "" {
		query += " AND type = ?"
		args = append(args, filters.Type)
	}
	if filters.Alias != "" {
		query += " AND alias = ?"
		args = append(args, filters.Alias)
	}
	if filters.IsDefault != nil {
		query += " AND is_default = ?"
		args = append(args, boolToInt(*filters.IsDefault))
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)
	}
	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}
	return query, args
}

// ListMetadata retrieves blob-free key projections (same filters/order as
// List) for listing surfaces that never need wrapped private-key material.
func (r *IdentityKeyRepository) ListMetadata(ctx context.Context, filters usecases.KeyFilters) ([]*entities.KeyMetadata, error) {
	query := `SELECT id, type, alias, fingerprint, public_key, storage_mode, created_at, expires_at, usage_count, is_default
	          FROM identity_keys WHERE 1=1`

	f, args := sqliteKeyFilterSQL(filters)
	query += f

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys (metadata): %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var keys []*entities.KeyMetadata
	for rows.Next() {
		m := &entities.KeyMetadata{}
		var createdAt, expiresAt sql.NullInt64
		var isDefault int
		var storageMode string

		err := rows.Scan(
			&m.ID, &m.Type, &m.Alias, &m.Fingerprint, &m.PublicKey,
			&storageMode, &createdAt, &expiresAt, &m.UsageCount, &isDefault,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key metadata: %w", err)
		}

		m.StorageMode = entities.StorageMode(storageMode)
		m.CreatedAt = time.Unix(createdAt.Int64, 0)
		if expiresAt.Valid {
			t := time.Unix(expiresAt.Int64, 0)
			m.ExpiresAt = &t
		}
		m.IsDefault = isDefault == 1
		keys = append(keys, m)
	}

	return keys, nil
}

// Update updates an identity key
func (r *IdentityKeyRepository) Update(ctx context.Context, key *entities.IdentityKey) error {
	if err := key.Validate(); err != nil {
		return err
	}

	var expiresAt *int64
	if key.ExpiresAt != nil {
		ts := key.ExpiresAt.Unix()
		expiresAt = &ts
	}

	_, err := r.db.ExecContext(ctx, `
		UPDATE identity_keys SET type = ?, alias = ?, fingerprint = ?, public_key = ?,
		wrapped_private_key = ?, argon2id_salt = ?, local_wrapped_key = ?, local_salt = ?,
		storage_mode = ?, storage_backend = ?,
		created_at = ?, expires_at = ?, usage_count = ?, is_default = ?
		WHERE id = ?
	`, key.Type, key.Alias, key.Fingerprint, key.PublicKey,
		key.WrappedPrivateKey, key.Argon2idSalt, key.LocalWrappedKey, key.LocalSalt,
		key.StorageMode, key.StorageBackend,
		key.CreatedAt.Unix(), expiresAt, key.UsageCount, boolToInt(key.IsDefault), key.ID)
	if err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	return nil
}

// Delete deletes an identity key
func (r *IdentityKeyRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM identity_keys WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	return nil
}

// Count returns the total number of identity keys
func (r *IdentityKeyRepository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM identity_keys").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count keys: %w", err)
	}
	return count, nil
}

// ListWithExpiry returns all keys whose expires_at column is non-null,
// across all users. Used by CheckExpiryUseCase to scan the full keyspace.
func (r *IdentityKeyRepository) ListWithExpiry(ctx context.Context) ([]*entities.IdentityKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+identityKeyCols+` FROM identity_keys WHERE expires_at IS NOT NULL ORDER BY expires_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys with expiry: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var keys []*entities.IdentityKey
	for rows.Next() {
		key, err := scanIdentityKey(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Close closes the database connection
func (r *IdentityKeyRepository) Close() error {
	return r.db.Close()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
