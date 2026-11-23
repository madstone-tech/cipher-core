package entities

import (
	"errors"
	"time"
)

// GrantStatus represents the status of a shared key grant
type GrantStatus string

const (
	GrantStatusActive  GrantStatus = "active"
	GrantStatusRevoked GrantStatus = "revoked"
)

// SharedKeyPolicy represents a named shared AES-256 key for a team or project.
// The actual key material is never stored; only a verification hash and
// per-grantee encrypted copies (SharedKeyGrant) exist.
type SharedKeyPolicy struct {
	ID        string
	Name      string // Human-readable policy name (e.g. "Project Alpha")
	OwnerID   string // User who created the policy
	KeyID     string // Identity key this share was minted from (for cascade revoke on key delete); may be empty for legacy policies
	KeyHash   string // SHA-256 of the plaintext AES-256 key (for verification)
	CreatedAt time.Time
	RevokedAt *time.Time
	IsActive  bool
}

// Validate checks if the shared key policy is valid
func (p *SharedKeyPolicy) Validate() error {
	if p.ID == "" {
		return errors.New("policy ID is required")
	}
	if p.Name == "" {
		return errors.New("policy name is required")
	}
	if p.OwnerID == "" {
		return errors.New("owner ID is required")
	}
	if p.KeyHash == "" {
		return errors.New("key hash is required")
	}
	if p.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if p.RevokedAt != nil && p.IsActive {
		return errors.New("revoked policy must not be active")
	}
	return nil
}

// SharedKeyGrant represents one grantee's encrypted copy of a shared key.
// The AES key is encrypted to the grantee's X25519 public key.
type SharedKeyGrant struct {
	ID                string
	PolicyID          string // FK to SharedKeyPolicy
	GranteeID         string // User receiving access
	EncryptedKeyBytes []byte // AES key encrypted to grantee's X25519 public key
	GrantedAt         time.Time
	RevokedAt         *time.Time
	Status            GrantStatus // active or revoked
}

// Validate checks if the shared key grant is valid
func (g *SharedKeyGrant) Validate() error {
	if g.ID == "" {
		return errors.New("grant ID is required")
	}
	if g.PolicyID == "" {
		return errors.New("policy ID is required")
	}
	if g.GranteeID == "" {
		return errors.New("grantee ID is required")
	}
	if len(g.EncryptedKeyBytes) == 0 {
		return errors.New("encrypted key bytes are required")
	}
	if g.GrantedAt.IsZero() {
		return errors.New("granted_at is required")
	}
	if g.Status != GrantStatusActive && g.Status != GrantStatusRevoked {
		return errors.New("invalid grant status: must be active or revoked")
	}
	return nil
}
