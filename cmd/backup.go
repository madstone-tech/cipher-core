package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// BackupFile represents the JSON backup format.
type BackupFile struct {
	Version   string         `json:"version"`
	CreatedAt time.Time      `json:"createdAt"`
	Keys      []BackupKey    `json:"keys"`
	Policies  []BackupPolicy `json:"policies"`
	Grants    []BackupGrant  `json:"grants"`
}

// BackupKey is the serialized form of an identity key.
type BackupKey struct {
	ID                string `json:"id"`
	Type              string `json:"type"`
	Alias             string `json:"alias"`
	Fingerprint       string `json:"fingerprint"`
	PublicKey         string `json:"publicKey"`
	WrappedPrivateKey string `json:"wrappedPrivateKey"`
	Argon2idSalt      string `json:"argon2idSalt"`
	StorageMode       string `json:"storageMode"`
	StorageBackend    string `json:"storageBackend"`
	IsDefault         bool   `json:"isDefault"`
	CreatedAt         string `json:"createdAt"`
}

// BackupPolicy is the serialized form of a shared key policy.
type BackupPolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	OwnerID   string `json:"ownerID"`
	KeyHash   string `json:"keyHash"`
	IsActive  bool   `json:"isActive"`
	CreatedAt string `json:"createdAt"`
}

// BackupGrant is the serialized form of a shared key grant.
type BackupGrant struct {
	ID                string `json:"id"`
	PolicyID          string `json:"policyID"`
	GranteeID         string `json:"granteeID"`
	EncryptedKeyBytes string `json:"encryptedKeyBytes"`
	Status            string `json:"status"`
	GrantedAt         string `json:"grantedAt"`
}

// BackupCommand handles key and policy backup.
type BackupCommand struct {
	dbPath string
}

// NewBackupCommand creates a new BackupCommand.
func NewBackupCommand(dbPath string) *BackupCommand {
	return &BackupCommand{dbPath: dbPath}
}

// Execute creates a backup file. With numbered (the default path), a taken
// name gets "-2", "-3", ... before ".json" instead of failing (T-10).
func (c *BackupCommand) Execute(ctx context.Context, outputPath string, numbered bool) error {
	fh := cli.NewFileHandler()
	if err := usecases.CheckOutputPath(fh, "", outputPath, protectedKeyStores(c.dbPath)); err != nil {
		return err
	}
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer adapters.Close() //nolint:errcheck // best-effort: read-only close (backup only reads the DB)

	// List all keys
	keys, err := adapters.KeyRepo.List(ctx, usecases.KeyFilters{})
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	// List all policies for the local owner
	ownerID := os.Getenv("MDSTN_OWNER_ID")
	if ownerID == "" {
		ownerID = "local-user"
	}
	policies, err := adapters.PolicyRepo.ListPolicies(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	backup := BackupFile{
		Version:   "1",
		CreatedAt: time.Now(),
	}

	for _, k := range keys {
		backup.Keys = append(backup.Keys, BackupKey{
			ID:                k.ID,
			Type:              string(k.Type),
			Alias:             k.Alias,
			Fingerprint:       k.Fingerprint,
			PublicKey:         base64.StdEncoding.EncodeToString(k.PublicKey),
			WrappedPrivateKey: base64.StdEncoding.EncodeToString(k.WrappedPrivateKey),
			Argon2idSalt:      base64.StdEncoding.EncodeToString(k.Argon2idSalt),
			StorageMode:       string(k.StorageMode),
			StorageBackend:    string(k.StorageBackend),
			IsDefault:         k.IsDefault,
			CreatedAt:         k.CreatedAt.Format(time.RFC3339),
		})
	}

	for _, p := range policies {
		backup.Policies = append(backup.Policies, BackupPolicy{
			ID:        p.ID,
			Name:      p.Name,
			OwnerID:   p.OwnerID,
			KeyHash:   p.KeyHash,
			IsActive:  p.IsActive,
			CreatedAt: p.CreatedAt.Format(time.RFC3339),
		})

		// Export grants for this policy
		grants, gErr := adapters.PolicyRepo.ListGrants(ctx, p.ID)
		if gErr != nil {
			return fmt.Errorf("failed to list grants for policy %s: %w", p.ID, gErr)
		}
		for _, g := range grants {
			backup.Grants = append(backup.Grants, BackupGrant{
				ID:                g.ID,
				PolicyID:          g.PolicyID,
				GranteeID:         g.GranteeID,
				EncryptedKeyBytes: base64.StdEncoding.EncodeToString(g.EncryptedKeyBytes),
				Status:            string(g.Status),
				GrantedAt:         g.GrantedAt.Format(time.RFC3339),
			})
		}
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup: %w", err)
	}

	// A backup never replaces a file, with or without -o: an old backup can be
	// the only copy of a key that was deleted since (S-6). The staged writer
	// writes a 0600 temp file and publishes it with a no-replace rename.
	if outputPath, err = publishBackup(ctx, fh, outputPath, data, numbered); err != nil {
		return err
	}

	fmt.Println("WARNING: Backup contains wrapped private keys. Store this file securely.")
	fmt.Printf("Backed up %d identity keys, %d shared key policies to %s\n",
		len(backup.Keys), len(backup.Policies), outputPath)
	return nil
}

// maxBackupSuffix bounds the "-N" names tried for one default backup path.
const maxBackupSuffix = 99

// publishBackup writes data to path without replacing a file. With numbered,
// a taken name is retried as "<name>-2.json", "<name>-3.json", ... It returns
// the path that was written.
func publishBackup(ctx context.Context, fh *cli.FileHandler, path string, data []byte, numbered bool) (string, error) {
	base := strings.TrimSuffix(path, ".json")
	for n := 1; ; n++ {
		candidate := path
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d.json", base, n)
		}
		err := writeBackupOnce(ctx, fh, candidate, data)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) || !numbered || n >= maxBackupSuffix {
			if errors.Is(err, fs.ErrExist) {
				return "", fmt.Errorf("backup %s already exists; it was not replaced: %w", candidate, err)
			}
			return "", err
		}
	}
}

func writeBackupOnce(ctx context.Context, fh *cli.FileHandler, path string, data []byte) error {
	w, err := fh.WriteStreamExclusive(path)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return errors.Join(fmt.Errorf("failed to write backup: %w", err), w.Abort())
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, w.Abort())
	}
	if err := w.Commit(); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		return fmt.Errorf("failed to finalize backup: %w", err)
	}
	return nil
}
