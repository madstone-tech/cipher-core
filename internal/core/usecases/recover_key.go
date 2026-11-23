package usecases

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// RecoverKey handles BIP39 mnemonic key recovery.
type RecoverKey struct {
	kekProvider  KEKProvider
	identityRepo IdentityKeyRepository
	crypto       CryptoEngine
	prompter     UserPrompter
	logger       Logger
}

// NewRecoverKey creates a new RecoverKey usecase.
func NewRecoverKey(
	kekProvider KEKProvider,
	identityRepo IdentityKeyRepository,
	crypto CryptoEngine,
	prompter UserPrompter,
	logger Logger,
) *RecoverKey {
	return &RecoverKey{
		kekProvider:  kekProvider,
		identityRepo: identityRepo,
		crypto:       crypto,
		prompter:     prompter,
		logger:       logger,
	}
}

// MnemonicDeriver derives X25519 keys from a BIP39 mnemonic.
type MnemonicDeriver func(mnemonic string) (publicKey, privateKey []byte, err error)

// RecoverFromMnemonic derives an X25519 keypair from a BIP39 mnemonic, wraps
// the private key with a user-supplied key passphrase (Argon2id), and stores
// or re-wraps it in the local repository. Interactive variant — inputs are
// gathered via the prompter.
func (uc *RecoverKey) RecoverFromMnemonic(ctx context.Context, deriver MnemonicDeriver) (*entities.IdentityKey, error) {
	mnemonic, err := uc.prompter.PromptString("Enter your 24-word recovery phrase: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery phrase: %w", err)
	}

	publicKey, privateKey, err := deriver(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid recovery phrase: %w", err)
	}
	defer uc.kekProvider.ZeroKEK(privateKey)

	passphrase, err := uc.prompter.PromptPassphrase("Enter a key passphrase: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read key passphrase: %w", err)
	}

	return uc.wrapAndStore(ctx, publicKey, privateKey, passphrase)
}

// RecoverFromMnemonicWith is the headless (SDK/MCP) variant of
// RecoverFromMnemonic: the mnemonic and key passphrase are supplied
// directly instead of gathered via the interactive prompter. The derivation,
// wrapping, and storage logic is identical.
func (uc *RecoverKey) RecoverFromMnemonicWith(ctx context.Context, mnemonic, passphrase string, deriver MnemonicDeriver) (*entities.IdentityKey, error) {
	if len(mnemonic) == 0 {
		return nil, fmt.Errorf("recovery phrase must not be empty")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("key passphrase must not be empty")
	}

	publicKey, privateKey, err := deriver(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid recovery phrase: %w", err)
	}
	defer uc.kekProvider.ZeroKEK(privateKey)

	return uc.wrapAndStore(ctx, publicKey, privateKey, passphrase)
}

// wrapAndStore is the shared tail of both recovery variants: it derives the
// KEK from the passphrase, wraps the private key, and stores or re-wraps the
// identity keyed by the public-key fingerprint.
func (uc *RecoverKey) wrapAndStore(ctx context.Context, publicKey, privateKey []byte, passphrase string) (*entities.IdentityKey, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("key passphrase must not be empty")
	}

	salt, err := uc.kekProvider.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	kek, err := uc.kekProvider.DeriveKEK(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer uc.kekProvider.ZeroKEK(kek)

	// Use the same hashing as the rest of the codebase.
	fingerprint := uc.crypto.Hash(publicKey)
	keyID := fingerprint[:16]

	wrappedKey, err := uc.kekProvider.WrapKey(privateKey, kek, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap private key: %w", err)
	}

	// Look up the key by fingerprint. Only entities.ErrNotFound means "create new";
	// any other error propagates (Principle X: explicit error handling).
	existing, err := uc.identityRepo.GetByFingerprint(ctx, fingerprint)
	if err != nil && !errors.Is(err, entities.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing key: %w", err)
	}

	if existing != nil {
		// Re-wrap path: update wrap material with the new passphrase.
		existing.WrappedPrivateKey = wrappedKey
		existing.Argon2idSalt = salt
		existing.StorageMode = entities.StorageModeStandard
		if err := uc.identityRepo.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to re-wrap existing key: %w", err)
		}
		uc.logger.Info("Key re-wrapped from recovery phrase (passphrase reset)", map[string]interface{}{
			"fingerprint": fingerprint,
		})
		return existing, nil
	}

	// Create new wrapped key.
	key := &entities.IdentityKey{
		ID:                keyID,
		Type:              entities.KeyTypeX25519,
		Alias:             "recovered",
		Fingerprint:       fingerprint,
		PublicKey:         publicKey,
		WrappedPrivateKey: wrappedKey,
		Argon2idSalt:      salt,
		CreatedAt:         time.Now(),
		IsDefault:         false,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	if err := uc.identityRepo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to store recovered key: %w", err)
	}

	uc.logger.Info("Key recovered from recovery phrase (new)", map[string]interface{}{
		"fingerprint": fingerprint,
	})

	return key, nil
}
