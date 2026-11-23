package usecases

import (
	"context"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// CreateKeyRequest contains parameters for key creation
type CreateKeyRequest struct {
	Type       entities.KeyType // Default: X25519
	Alias      string
	Expires    *time.Time
	Passphrase string // If set, used directly instead of prompting via UserPrompter
}

// CreateKeyResponse contains the result of key creation
type CreateKeyResponse struct {
	Key      *entities.IdentityKey
	Mnemonic string
}

// CreateKey creates a new encryption key
type CreateKey struct {
	keyRepo      KeyRepository
	crypto       CryptoEngine
	kekProvider  KEKProvider
	sessionStore SessionStore
	prompter     UserPrompter
	logger       Logger
}

// NewCreateKey creates a new CreateKey usecase
func NewCreateKey(
	keyRepo KeyRepository,
	crypto CryptoEngine,
	kekProvider KEKProvider,
	sessionStore SessionStore,
	prompter UserPrompter,
	logger Logger,
) *CreateKey {
	return &CreateKey{
		keyRepo:      keyRepo,
		crypto:       crypto,
		kekProvider:  kekProvider,
		sessionStore: sessionStore,
		prompter:     prompter,
		logger:       logger,
	}
}

// Execute creates a new key
func (uc *CreateKey) Execute(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	if uc.kekProvider == nil || uc.sessionStore == nil {
		return nil, fmt.Errorf("key creation requires KEKProvider and SessionStore")
	}

	// Default to X25519 if not specified
	keyType := req.Type
	if keyType == "" {
		keyType = entities.KeyTypeX25519
	}

	// Validate key type
	if keyType != entities.KeyTypeX25519 {
		return nil, fmt.Errorf("cannot create key of type %s (only X25519 supported)", keyType)
	}

	// Generate a BIP39 mnemonic and derive the X25519 keypair from it
	mnemonic, err := uc.crypto.GenerateMnemonic()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	var publicKey, privateKey []byte

	switch keyType {
	case entities.KeyTypeX25519:
		publicKey, privateKey, err = uc.crypto.DeriveX25519FromMnemonic(mnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to derive X25519 keypair from mnemonic: %w", err)
		}
	}

	// Compute fingerprint from public key
	fingerprintData := privateKey
	if publicKey != nil {
		fingerprintData = publicKey
	}
	fingerprint := uc.crypto.Hash(fingerprintData)

	// Get passphrase: from request (server mode) or prompter (CLI mode)
	passphrase := req.Passphrase
	if passphrase == "" {
		if uc.prompter == nil {
			return nil, fmt.Errorf("passphrase is required for key creation")
		}
		passphrase, err = uc.prompter.PromptPassphrase("Enter a key passphrase: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	salt, err := uc.kekProvider.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	kek, err := uc.kekProvider.DeriveKEK(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	wrappedKey, err := uc.kekProvider.WrapKey(privateKey, kek, fingerprint[:16])
	if err != nil {
		uc.kekProvider.ZeroKEK(kek)
		return nil, fmt.Errorf("failed to wrap private key: %w", err)
	}

	// Zero raw private key bytes — only the wrapped form is stored
	uc.kekProvider.ZeroKEK(privateKey)

	// Create key entity with wrapped private key
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              keyType,
		Alias:             req.Alias,
		Fingerprint:       fingerprint,
		PublicKey:         publicKey,
		WrappedPrivateKey: wrappedKey,
		Argon2idSalt:      salt,
		CreatedAt:         time.Now(),
		ExpiresAt:         req.Expires,
		UsageCount:        0,
		IsDefault:         false,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	// Store key
	if err := uc.keyRepo.Create(ctx, key); err != nil {
		uc.kekProvider.ZeroKEK(kek)
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	// Cache the KEK for the session (the session store's configured TTL).
	if err := uc.sessionStore.SetKEK(key.ID, kek, 0); err != nil {
		uc.logger.Warn("Failed to cache KEK for session", map[string]interface{}{"key_id": key.ID, "error": err.Error()})
	}
	uc.kekProvider.ZeroKEK(kek)

	uc.logger.Info("Created new key", map[string]interface{}{
		"type":        keyType,
		"alias":       req.Alias,
		"fingerprint": fingerprint,
	})

	return &CreateKeyResponse{Key: key, Mnemonic: mnemonic}, nil
}
