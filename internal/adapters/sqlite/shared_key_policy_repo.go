package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// SharedKeyPolicyRepository implements SharedKeyPolicyRepository using SQLite.
type SharedKeyPolicyRepository struct {
	db *sql.DB
}

// NewSharedKeyPolicyRepository creates a new SQLite-backed policy repository.
// It shares the DB connection from IdentityKeyRepository.
func NewSharedKeyPolicyRepository(db *sql.DB) (*SharedKeyPolicyRepository, error) {
	repo := &SharedKeyPolicyRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SharedKeyPolicyRepository) migrate() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS shared_key_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		owner_id TEXT NOT NULL,
		key_id TEXT NOT NULL DEFAULT '',
		key_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		revoked_at INTEGER,
		is_active INTEGER DEFAULT 1
	)`)
	if err != nil {
		return fmt.Errorf("create shared_key_policies table: %w", err)
	}
	// Add key_id to pre-existing databases (no-op once the column exists).
	if _, err := r.db.Exec(`ALTER TABLE shared_key_policies ADD COLUMN key_id TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("add key_id column: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_shared_key_policies_key_id ON shared_key_policies(key_id)`); err != nil {
		return fmt.Errorf("create key_id index: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_shared_key_policies_owner ON shared_key_policies(owner_id)`); err != nil {
		return fmt.Errorf("create owner index: %w", err)
	}
	_, err = r.db.Exec(`CREATE TABLE IF NOT EXISTS shared_key_grants (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL REFERENCES shared_key_policies(id),
		grantee_id TEXT NOT NULL,
		encrypted_key_bytes BLOB,
		granted_at INTEGER NOT NULL,
		revoked_at INTEGER,
		status TEXT NOT NULL DEFAULT 'active'
	)`)
	if err != nil {
		return fmt.Errorf("create shared_key_grants table: %w", err)
	}
	return nil
}

func (r *SharedKeyPolicyRepository) CreatePolicy(ctx context.Context, policy *entities.SharedKeyPolicy) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO shared_key_policies (id, name, owner_id, key_id, key_hash, created_at, is_active)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		policy.ID, policy.Name, policy.OwnerID, policy.KeyID, policy.KeyHash,
		policy.CreatedAt.Unix(), boolToInt(policy.IsActive),
	)
	if err != nil {
		return fmt.Errorf("create policy: %w", err)
	}
	return nil
}

func (r *SharedKeyPolicyRepository) GetPolicy(ctx context.Context, id string) (*entities.SharedKeyPolicy, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, owner_id, key_id, key_hash, created_at, revoked_at, is_active
		 FROM shared_key_policies WHERE id = ?`, id)
	return scanPolicy(row)
}

func (r *SharedKeyPolicyRepository) ListPolicies(ctx context.Context, ownerID string) ([]*entities.SharedKeyPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, owner_id, key_id, key_hash, created_at, revoked_at, is_active
		 FROM shared_key_policies WHERE owner_id = ? ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var policies []*entities.SharedKeyPolicy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (r *SharedKeyPolicyRepository) RevokePolicy(ctx context.Context, id string) error {
	now := time.Now().Unix()
	_, err := r.db.ExecContext(ctx,
		`UPDATE shared_key_policies SET is_active = 0, revoked_at = ? WHERE id = ?`,
		now, id)
	if err != nil {
		return fmt.Errorf("revoke policy: %w", err)
	}
	// Revoke all active grants and clear encrypted bytes
	_, err = r.db.ExecContext(ctx,
		`UPDATE shared_key_grants SET status = 'revoked', revoked_at = ?, encrypted_key_bytes = NULL
		 WHERE policy_id = ? AND status = 'active'`, now, id)
	if err != nil {
		return fmt.Errorf("revoke policy grants: %w", err)
	}
	return nil
}

// RevokePoliciesByKeyID revokes every active policy minted from the given
// identity key and owned by ownerID, plus all of their active grants. Returns
// the number of policies revoked; a blank keyID is a no-op.
func (r *SharedKeyPolicyRepository) RevokePoliciesByKeyID(ctx context.Context, keyID, ownerID string) (int, error) {
	if keyID == "" {
		return 0, nil
	}
	now := time.Now().Unix()
	if _, err := r.db.ExecContext(ctx,
		`UPDATE shared_key_grants SET status = 'revoked', revoked_at = ?, encrypted_key_bytes = NULL
		 WHERE status = 'active' AND policy_id IN (
		     SELECT id FROM shared_key_policies WHERE key_id = ? AND owner_id = ? AND is_active = 1
		 )`, now, keyID, ownerID); err != nil {
		return 0, fmt.Errorf("revoke grants by key: %w", err)
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE shared_key_policies SET is_active = 0, revoked_at = ?
		 WHERE key_id = ? AND owner_id = ? AND is_active = 1`, now, keyID, ownerID)
	if err != nil {
		return 0, fmt.Errorf("revoke policies by key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke policies by key: rows affected: %w", err)
	}
	return int(n), nil
}

func (r *SharedKeyPolicyRepository) CreateGrant(ctx context.Context, grant *entities.SharedKeyGrant) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO shared_key_grants (id, policy_id, grantee_id, encrypted_key_bytes, granted_at, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		grant.ID, grant.PolicyID, grant.GranteeID, grant.EncryptedKeyBytes,
		grant.GrantedAt.Unix(), string(grant.Status),
	)
	if err != nil {
		return fmt.Errorf("create grant: %w", err)
	}
	return nil
}

func (r *SharedKeyPolicyRepository) GetGrant(ctx context.Context, policyID, granteeID string) (*entities.SharedKeyGrant, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, policy_id, grantee_id, encrypted_key_bytes, granted_at, revoked_at, status
		 FROM shared_key_grants WHERE policy_id = ? AND grantee_id = ?`, policyID, granteeID)
	return scanGrant(row)
}

func (r *SharedKeyPolicyRepository) ListGrants(ctx context.Context, policyID string) ([]*entities.SharedKeyGrant, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, policy_id, grantee_id, encrypted_key_bytes, granted_at, revoked_at, status
		 FROM shared_key_grants WHERE policy_id = ? ORDER BY granted_at DESC`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var grants []*entities.SharedKeyGrant
	for rows.Next() {
		g, err := scanGrantRow(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (r *SharedKeyPolicyRepository) ListGrantsForUser(ctx context.Context, granteeID string) ([]*entities.SharedKeyGrant, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, policy_id, grantee_id, encrypted_key_bytes, granted_at, revoked_at, status
		 FROM shared_key_grants WHERE grantee_id = ? ORDER BY granted_at DESC`, granteeID)
	if err != nil {
		return nil, fmt.Errorf("list grants for user: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort: read-only close

	var grants []*entities.SharedKeyGrant
	for rows.Next() {
		g, err := scanGrantRow(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (r *SharedKeyPolicyRepository) RevokeGrant(ctx context.Context, id string) error {
	now := time.Now().Unix()
	_, err := r.db.ExecContext(ctx,
		`UPDATE shared_key_grants SET status = 'revoked', revoked_at = ?, encrypted_key_bytes = NULL
		 WHERE id = ?`, now, id)
	if err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}
	return nil
}

// --- scan helpers ---

func scanPolicy(row *sql.Row) (*entities.SharedKeyPolicy, error) {
	var p entities.SharedKeyPolicy
	var createdAt int64
	var revokedAt sql.NullInt64
	var isActive int

	err := row.Scan(&p.ID, &p.Name, &p.OwnerID, &p.KeyID, &p.KeyHash, &createdAt, &revokedAt, &isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, entities.ErrNotFound
		}
		return nil, fmt.Errorf("scan policy: %w", err)
	}

	p.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		p.RevokedAt = &t
	}
	p.IsActive = isActive == 1
	return &p, nil
}

type policyScanner interface {
	Scan(dest ...interface{}) error
}

func scanPolicyRow(row policyScanner) (*entities.SharedKeyPolicy, error) {
	var p entities.SharedKeyPolicy
	var createdAt int64
	var revokedAt sql.NullInt64
	var isActive int

	err := row.Scan(&p.ID, &p.Name, &p.OwnerID, &p.KeyID, &p.KeyHash, &createdAt, &revokedAt, &isActive)
	if err != nil {
		return nil, fmt.Errorf("scan policy row: %w", err)
	}

	p.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		p.RevokedAt = &t
	}
	p.IsActive = isActive == 1
	return &p, nil
}

func scanGrant(row *sql.Row) (*entities.SharedKeyGrant, error) {
	var g entities.SharedKeyGrant
	var grantedAt int64
	var revokedAt sql.NullInt64
	var status string
	var encBytes []byte

	err := row.Scan(&g.ID, &g.PolicyID, &g.GranteeID, &encBytes, &grantedAt, &revokedAt, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, entities.ErrNotFound
		}
		return nil, fmt.Errorf("scan grant: %w", err)
	}

	g.EncryptedKeyBytes = encBytes
	g.GrantedAt = time.Unix(grantedAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		g.RevokedAt = &t
	}
	g.Status = entities.GrantStatus(status)
	return &g, nil
}

func scanGrantRow(row policyScanner) (*entities.SharedKeyGrant, error) {
	var g entities.SharedKeyGrant
	var grantedAt int64
	var revokedAt sql.NullInt64
	var status string
	var encBytes []byte

	err := row.Scan(&g.ID, &g.PolicyID, &g.GranteeID, &encBytes, &grantedAt, &revokedAt, &status)
	if err != nil {
		return nil, fmt.Errorf("scan grant row: %w", err)
	}

	g.EncryptedKeyBytes = encBytes
	g.GrantedAt = time.Unix(grantedAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		g.RevokedAt = &t
	}
	g.Status = entities.GrantStatus(status)
	return &g, nil
}
