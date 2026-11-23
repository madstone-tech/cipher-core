package usecases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// StoreWrappedKeyRequest contains parameters for storing a client-wrapped key.
// The browser generates the X25519 keypair and wraps the private key itself;
// the server stores only the public key, wrapped private key, and Argon2id salt
// — it never sees the raw private key or the passphrase.
type StoreWrappedKeyRequest struct {
	Alias             string
	Type              entities.KeyType
	PublicKey         []byte
	WrappedPrivateKey []byte
	Argon2idSalt      []byte
}

// StoreWrappedKey stores a client-wrapped identity key (zero-knowledge path).
type StoreWrappedKey struct {
	keyRepo KeyRepository
	logger  Logger
}

// NewStoreWrappedKey creates a new StoreWrappedKey usecase.
func NewStoreWrappedKey(keyRepo KeyRepository, logger Logger) *StoreWrappedKey {
	return &StoreWrappedKey{
		keyRepo: keyRepo,
		logger:  logger,
	}
}

// Execute validates and persists the client-wrapped key.
//
// Validation rules (mirroring the server-side path):
//   - Type must be entities.KeyTypeX25519 (defaults to it when empty)
//   - len(PublicKey) == 32  (X25519 raw public key)
//   - len(WrappedPrivateKey) >= 28  (12-byte nonce + 16-byte AES-GCM tag minimum)
//   - len(Argon2idSalt) == 16
func (uc *StoreWrappedKey) Execute(ctx context.Context, req *StoreWrappedKeyRequest) (*entities.IdentityKey, error) {
	// Default to X25519 when the caller omits the type.
	keyType := req.Type
	if keyType == "" {
		keyType = entities.KeyTypeX25519
	}

	if keyType != entities.KeyTypeX25519 {
		return nil, fmt.Errorf("unsupported key type %q: only x25519 is accepted on the wrapped-key path", keyType)
	}
	if len(req.PublicKey) != 32 {
		return nil, fmt.Errorf("public_key must be 32 bytes for X25519 (got %d)", len(req.PublicKey))
	}
	// AES-256-GCM: 12-byte nonce + ciphertext + 16-byte tag → minimum 28 bytes.
	if len(req.WrappedPrivateKey) < 28 {
		return nil, fmt.Errorf("wrapped_private_key too short: must be at least 28 bytes (nonce + tag), got %d", len(req.WrappedPrivateKey))
	}
	if len(req.Argon2idSalt) != 16 {
		return nil, fmt.Errorf("argon2id_salt must be exactly 16 bytes (got %d)", len(req.Argon2idSalt))
	}

	// Compute fingerprint the same way create_key.go does: SHA-256 hex of the public key.
	sum := sha256.Sum256(req.PublicKey)
	fingerprint := hex.EncodeToString(sum[:])
	keyID := fingerprint[:16]

	// Re-wrap path: if a key with this deterministic ID already exists, update
	// its wrap material (passphrase reset) instead of creating a duplicate.
	// Only entities.ErrNotFound means "create new"; any other error propagates.
	existing, err := uc.keyRepo.GetByID(ctx, keyID)
	if err != nil && !errors.Is(err, entities.ErrNotFound) {
		// Unexpected repository error — propagate it.
		return nil, fmt.Errorf("idempotency check failed: %w", err)
	}
	if existing != nil {
		// Update wrap material with the new passphrase's output.
		existing.WrappedPrivateKey = req.WrappedPrivateKey
		existing.Argon2idSalt = req.Argon2idSalt
		// Only overwrite alias when the caller supplies one; never clobber with "".
		if req.Alias != "" {
			existing.Alias = req.Alias
		}
		if err := uc.keyRepo.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to re-wrap existing key: %w", err)
		}
		uc.logger.Info("re-wrapped existing key (passphrase reset)", map[string]interface{}{
			"id":          keyID,
			"fingerprint": fingerprint,
		})
		return existing, nil
	}

	key := &entities.IdentityKey{
		ID:                keyID,
		Type:              keyType,
		Alias:             req.Alias,
		Fingerprint:       fingerprint,
		PublicKey:         req.PublicKey,
		WrappedPrivateKey: req.WrappedPrivateKey,
		Argon2idSalt:      req.Argon2idSalt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
		CreatedAt:         time.Now(),
		UsageCount:        0,
		IsDefault:         false,
	}

	if err := uc.keyRepo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to store wrapped key: %w", err)
	}

	uc.logger.Info("Stored client-wrapped key", map[string]interface{}{
		"fingerprint": fingerprint,
		"alias":       req.Alias,
		"type":        keyType,
	})

	return key, nil
}
