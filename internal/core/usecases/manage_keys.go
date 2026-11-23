package usecases

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// ListKeysRequest contains parameters for listing keys
type ListKeysRequest struct {
	Filters KeyFilters
}

// ListKeysResponse contains the list of keys
type ListKeysResponse struct {
	Keys []*entities.IdentityKey
}

// ListKeysMetadataResponse contains blob-free key projections for listing
// surfaces.  See ManageKeys.ListKeysMetadata.
type ListKeysMetadataResponse struct {
	Keys []*entities.KeyMetadata
}

// GetKeyRequest contains parameters for getting a key
type GetKeyRequest struct {
	ID string
}

// GetKeyResponse contains the key
type GetKeyResponse struct {
	Key *entities.IdentityKey
}

// DeleteKeyRequest contains parameters for deleting a key
type DeleteKeyRequest struct {
	ID string
}

// AliasKeyRequest contains parameters for aliasing a key
type AliasKeyRequest struct {
	ID    string
	Alias string
}

// ExportKeyRequest contains parameters for exporting a key
type ExportKeyRequest struct {
	ID     string
	Format string // "pem" or "raw"
}

// ExportKeyResponse contains the exported key data
type ExportKeyResponse struct {
	Data []byte
}

// ManageKeys provides key management operations
type ManageKeys struct {
	keyRepo KeyRepository
	logger  Logger
}

// NewManageKeys creates a new ManageKeys usecase
func NewManageKeys(
	keyRepo KeyRepository,
	logger Logger,
) *ManageKeys {
	return &ManageKeys{
		keyRepo: keyRepo,
		logger:  logger,
	}
}

// ListKeys lists all keys with optional filters
func (uc *ManageKeys) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	keys, err := uc.keyRepo.List(ctx, req.Filters)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	return &ListKeysResponse{Keys: keys}, nil
}

// ListKeysMetadata lists keys as blob-free projections.  Listing surfaces
// (HTTP keys list) MUST use this rather than ListKeys: it avoids transferring
// wrapped private-key material from the database for rows that will never be
// unwrapped server-side (zero-knowledge — unwrapping is client-side).
func (uc *ManageKeys) ListKeysMetadata(ctx context.Context, req *ListKeysRequest) (*ListKeysMetadataResponse, error) {
	keys, err := uc.keyRepo.ListMetadata(ctx, req.Filters)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys (metadata): %w", err)
	}

	return &ListKeysMetadataResponse{Keys: keys}, nil
}

// GetKey retrieves a specific key
func (uc *ManageKeys) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	key, err := uc.keyRepo.GetByID(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return &GetKeyResponse{Key: key}, nil
}

// DeleteKey deletes a key
func (uc *ManageKeys) DeleteKey(ctx context.Context, req *DeleteKeyRequest) error {
	// Check if key exists
	key, err := uc.keyRepo.GetByID(ctx, req.ID)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	// Don't allow deleting the default key if it's the only key
	if key.IsDefault {
		count, err := uc.keyRepo.Count(ctx)
		if err != nil {
			return fmt.Errorf("failed to count keys: %w", err)
		}
		if count == 1 {
			return fmt.Errorf("cannot delete the only key")
		}
	}

	if err := uc.keyRepo.Delete(ctx, req.ID); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	uc.logger.Info("Deleted key", map[string]interface{}{
		"key_id": req.ID,
	})

	return nil
}

// AliasKey sets an alias for a key
func (uc *ManageKeys) AliasKey(ctx context.Context, req *AliasKeyRequest) error {
	key, err := uc.keyRepo.GetByID(ctx, req.ID)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	key.Alias = req.Alias

	if err := uc.keyRepo.Update(ctx, key); err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	uc.logger.Info("Updated key alias", map[string]interface{}{
		"key_id": req.ID,
		"alias":  req.Alias,
	})

	return nil
}

// ExportKey exports a key in the specified format
func (uc *ManageKeys) ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error) {
	key, err := uc.keyRepo.GetByID(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	var data []byte

	switch req.Format {
	case "pem":
		// Export as PEM format
		var blockType string
		var keyData []byte

		switch key.Type {
		case entities.KeyTypeX25519:
			// The bytes are the WRAPPED private key (nonce, ciphertext, tag),
			// not a raw X25519 key: the label says so (T-8).
			blockType = "MDSTN WRAPPED X25519 PRIVATE KEY"
			keyData = key.WrappedPrivateKey
		default:
			return nil, fmt.Errorf("unsupported key type for PEM export: %s", key.Type)
		}

		block := &pem.Block{
			Type:  blockType,
			Bytes: keyData,
		}
		data = pem.EncodeToMemory(block)

	case "raw", "":
		// Export raw bytes
		data = key.WrappedPrivateKey

	default:
		return nil, fmt.Errorf("unsupported export format: %s", req.Format)
	}

	return &ExportKeyResponse{Data: data}, nil
}
