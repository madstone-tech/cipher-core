package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// RestoreCommand handles key and policy restoration from backup.
type RestoreCommand struct {
	dbPath string
}

// NewRestoreCommand creates a new RestoreCommand.
func NewRestoreCommand(dbPath string) *RestoreCommand {
	return &RestoreCommand{dbPath: dbPath}
}

// Execute restores from a backup file.
func (c *RestoreCommand) Execute(ctx context.Context, backupPath string, force bool) (retErr error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var backup BackupFile
	if err := json.Unmarshal(data, &backup); err != nil {
		return fmt.Errorf("failed to parse backup file: %w", err)
	}

	if backup.Version != "1" {
		return fmt.Errorf("unsupported backup version: %s (expected \"1\")", backup.Version)
	}

	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	var keysRestored, keysSkipped, keysFailed int
	var policiesRestored, policiesSkipped, policiesFailed int
	var grantsRestored, grantsFailed int

	// Restore keys
	for _, bk := range backup.Keys {
		pubKey, err := base64.StdEncoding.DecodeString(bk.PublicKey)
		if err != nil {
			fmt.Printf("  Failed key %s: invalid publicKey base64: %v\n", safeTrunc(bk.Alias, 20), err)
			keysFailed++
			continue
		}
		wrappedKey, err := base64.StdEncoding.DecodeString(bk.WrappedPrivateKey)
		if err != nil {
			fmt.Printf("  Failed key %s: invalid wrappedPrivateKey base64: %v\n", safeTrunc(bk.Alias, 20), err)
			keysFailed++
			continue
		}
		salt, err := base64.StdEncoding.DecodeString(bk.Argon2idSalt)
		if err != nil {
			fmt.Printf("  Failed key %s: invalid argon2idSalt base64: %v\n", safeTrunc(bk.Alias, 20), err)
			keysFailed++
			continue
		}
		createdAt, err := time.Parse(time.RFC3339, bk.CreatedAt)
		if err != nil {
			fmt.Printf("  Failed key %s: invalid createdAt: %v\n", safeTrunc(bk.Alias, 20), err)
			keysFailed++
			continue
		}

		existing, lookupErr := adapters.KeyRepo.GetByFingerprint(ctx, bk.Fingerprint)
		if lookupErr == nil && existing != nil {
			if !force {
				fmt.Printf("  Skip key %s (%s) — already exists\n", bk.Alias, safeTrunc(bk.Fingerprint, 8))
				keysSkipped++
				continue
			}
			// Overwrite all fields
			existing.Alias = bk.Alias
			existing.Type = entities.KeyType(bk.Type)
			existing.Alias = bk.Alias
			existing.PublicKey = pubKey
			existing.WrappedPrivateKey = wrappedKey
			existing.Argon2idSalt = salt
			existing.StorageMode = entities.StorageMode(bk.StorageMode)
			existing.StorageBackend = entities.StorageBackend(bk.StorageBackend)
			existing.IsDefault = bk.IsDefault
			existing.CreatedAt = createdAt
			if err := adapters.KeyRepo.Update(ctx, existing); err != nil {
				fmt.Printf("  Failed to update key %s: %v\n", bk.Alias, err)
				keysFailed++
				continue
			}
			keysRestored++
			continue
		}

		key := &entities.IdentityKey{
			ID:                bk.ID,
			Type:              entities.KeyType(bk.Type),
			Alias:             bk.Alias,
			Fingerprint:       bk.Fingerprint,
			PublicKey:         pubKey,
			WrappedPrivateKey: wrappedKey,
			Argon2idSalt:      salt,
			StorageMode:       entities.StorageMode(bk.StorageMode),
			StorageBackend:    entities.StorageBackend(bk.StorageBackend),
			IsDefault:         bk.IsDefault,
			CreatedAt:         createdAt,
		}

		if err := adapters.KeyRepo.Create(ctx, key); err != nil {
			fmt.Printf("  Failed to create key %s: %v\n", bk.Alias, err)
			keysFailed++
			continue
		}
		keysRestored++
	}

	// Restore policies
	for _, bp := range backup.Policies {
		createdAt, err := time.Parse(time.RFC3339, bp.CreatedAt)
		if err != nil {
			fmt.Printf("  Failed policy %s: invalid createdAt: %v\n", safeTrunc(bp.Name, 20), err)
			policiesFailed++
			continue
		}

		existing, lookupErr := adapters.PolicyRepo.GetPolicy(ctx, bp.ID)
		if lookupErr == nil && existing != nil {
			if !force {
				fmt.Printf("  Skip policy %s (%s) — already exists\n", bp.Name, safeTrunc(bp.ID, 8))
				policiesSkipped++
				continue
			}
			// Force: revoke and recreate
			if err := adapters.PolicyRepo.RevokePolicy(ctx, bp.ID); err != nil {
				fmt.Printf("  Failed to revoke existing policy %s: %v\n", bp.Name, err)
				policiesFailed++
				continue
			}
		}

		policy := &entities.SharedKeyPolicy{
			ID:        bp.ID,
			Name:      bp.Name,
			OwnerID:   bp.OwnerID,
			KeyHash:   bp.KeyHash,
			IsActive:  bp.IsActive,
			CreatedAt: createdAt,
		}

		if err := adapters.PolicyRepo.CreatePolicy(ctx, policy); err != nil {
			fmt.Printf("  Failed to create policy %s: %v\n", bp.Name, err)
			policiesFailed++
			continue
		}
		policiesRestored++
	}

	// Restore grants
	for _, bg := range backup.Grants {
		encBytes, err := base64.StdEncoding.DecodeString(bg.EncryptedKeyBytes)
		if err != nil {
			fmt.Printf("  Failed grant %s: invalid base64: %v\n", safeTrunc(bg.ID, 8), err)
			grantsFailed++
			continue
		}
		grantedAt, err := time.Parse(time.RFC3339, bg.GrantedAt)
		if err != nil {
			fmt.Printf("  Failed grant %s: invalid grantedAt: %v\n", safeTrunc(bg.ID, 8), err)
			grantsFailed++
			continue
		}

		grant := &entities.SharedKeyGrant{
			ID:                bg.ID,
			PolicyID:          bg.PolicyID,
			GranteeID:         bg.GranteeID,
			EncryptedKeyBytes: encBytes,
			Status:            entities.GrantStatus(bg.Status),
			GrantedAt:         grantedAt,
		}

		if err := adapters.PolicyRepo.CreateGrant(ctx, grant); err != nil {
			fmt.Printf("  Failed to create grant %s: %v\n", safeTrunc(bg.ID, 8), err)
			grantsFailed++
			continue
		}
		grantsRestored++
	}

	totalFailed := keysFailed + policiesFailed + grantsFailed
	totalSkipped := keysSkipped + policiesSkipped
	fmt.Printf("Restored %d keys, %d policies, %d grants (%d skipped, %d failed)\n",
		keysRestored, policiesRestored, grantsRestored, totalSkipped, totalFailed)

	if totalFailed > 0 {
		return fmt.Errorf("%d items failed to restore", totalFailed)
	}
	return nil
}

// safeTrunc safely truncates a string to maxLen.
func safeTrunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
