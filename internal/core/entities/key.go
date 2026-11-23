package entities

import (
	"errors"
	"time"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeX25519 KeyType = "x25519"
)

// StorageMode represents the trust mode for private key storage
type StorageMode string

const (
	StorageModeStandard StorageMode = "standard" // Argon2id-wrapped private key + salt
	StorageModeAdvanced StorageMode = "advanced" // Public key only; private key never leaves client
)

// StorageBackend represents where the key material is persisted
type StorageBackend string

const (
	StorageBackendSQLite        StorageBackend = "sqlite"
	StorageBackendPostgres      StorageBackend = "postgres"
	StorageBackendKeychain      StorageBackend = "keychain"       // Future: macOS Keychain
	StorageBackendSecureEnclave StorageBackend = "secure_enclave" // Future: Secure Enclave
)

// IdentityKey represents a user's cryptographic identity key.
// Private key bytes are NEVER stored raw at rest. In Standard mode they are
// Argon2id-wrapped; in Advanced mode they exist only on the client.
type IdentityKey struct {
	ID string
	// UserID is the owning user's ID. Populated in cross-tenant scans
	// (e.g. ListWithExpiry on the server) and left empty in single-user
	// SQLite (CLI) mode where ownership is implicit.
	UserID            string
	Type              KeyType
	Alias             string
	Fingerprint       string      // SHA-256 of public key
	PublicKey         []byte      // Always present
	WrappedPrivateKey []byte      // Argon2id-wrapped (standard) or nil (advanced)
	Argon2idSalt      []byte      // 16-byte salt for standard mode wrapping
	LocalWrappedKey   []byte      // Future: OS-level wrapped copy
	LocalSalt         []byte      // Future: OS-level salt
	StorageMode       StorageMode // "standard" or "advanced"
	StorageBackend    StorageBackend
	CreatedAt         time.Time
	ExpiresAt         *time.Time
	UsageCount        int64
	IsDefault         bool
}

// Validate checks if the identity key is valid
func (k *IdentityKey) Validate() error {
	if k.ID == "" {
		return errors.New("key ID is required")
	}
	if k.Type == "" {
		return errors.New("key type is required")
	}
	if k.Type != KeyTypeX25519 {
		return errors.New("invalid key type: must be x25519")
	}
	if k.Fingerprint == "" {
		return errors.New("fingerprint is required")
	}
	if len(k.PublicKey) == 0 {
		return errors.New("public key is required")
	}
	if k.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if k.StorageMode == "" {
		return errors.New("storage mode is required")
	}

	switch k.StorageMode {
	case StorageModeStandard:
		if len(k.WrappedPrivateKey) == 0 {
			return errors.New("wrapped private key is required for standard mode")
		}
		// Argon2idSalt may be nil for migrated keys in transitional state (pre-wrapping)
	case StorageModeAdvanced:
		if len(k.WrappedPrivateKey) > 0 {
			return errors.New("wrapped private key must be nil for advanced mode")
		}
	default:
		return errors.New("invalid storage mode: must be standard or advanced")
	}

	return nil
}

// IsExpired checks if the key has expired
func (k *IdentityKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IncrementUsage increments the usage counter
func (k *IdentityKey) IncrementUsage() {
	k.UsageCount++
}

// IsExpired checks if the key has expired
func (m *KeyMetadata) IsExpired() bool {
	if m.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*m.ExpiresAt)
}

// KeyMetadata is the blob-free projection of IdentityKey for list-style
// reads.  It carries everything any listing consumer needs (CLI table,
// dropdowns, MCP list, expiry sweep) and excludes private-key
// material: WrappedPrivateKey, Argon2idSalt, LocalWrappedKey, LocalSalt, and
// StorageBackend (a create-time concern only).
//
// Material-bearing reads go through IdentityKeyRepository.List / GetByID.
// PublicKey IS included: it is not key *material* at rest (public by
// definition) and list consumers (CLI keys publish, browser share modal)
// display or transmit it.
type KeyMetadata struct {
	ID          string
	UserID      string
	Type        KeyType
	Alias       string
	Fingerprint string
	PublicKey   []byte
	StorageMode StorageMode
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	UsageCount  int64
	IsDefault   bool
}
