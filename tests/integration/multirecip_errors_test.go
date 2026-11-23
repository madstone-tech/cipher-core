package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	sqlite "github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// TestMultiRecipientErrorPaths covers the encryption-time and decrypt-time
// error contract:
//   - encrypt with 0 recipients → ErrNoRecipients
//   - encrypt with >16 recipients → ErrTooManyRecipients
//   - decrypt with a corrupted recipient block → parse/decrypt error, not a panic
func TestMultiRecipientErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := filepath.Join(tmpDir, "test.txt")

	testData := []byte("error-path test payload")
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyRepo.Close()

	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())
	cryptoEngine := crypto.NewEngine()
	encoder := crypto.NewFileEncoder()
	ckdClient := ckd.NewClient(ckdCache)
	fileHandler := cli.NewFileHandler()
	progress := &noopProgress{}
	prompter := &yesPrompter{}
	logger := logging.NewSimpleLogger()
	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(ctx)
	defer sessionStore.Stop()

	lookupKeyUC := usecases.NewLookupKey(ckdClient, ckdCache, logger)
	encryptUC := usecases.NewEncryptFile(keyRepo, recoveryRepo, cryptoEngine, kekProvider, sessionStore, encoder, lookupKeyUC, fileHandler, progress, prompter, logger)
	decryptUC := usecases.NewDecryptFile(keyRepo, cryptoEngine, kekProvider, sessionStore, encoder, fileHandler, progress, prompter, logger)

	// One real recipient so valid-baseline encryption works.
	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	kp := "error-path-passphrase"
	resp, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{Type: "x25519", Alias: "r1", Passphrase: kp})
	if err != nil {
		t.Fatal(err)
	}
	oneRecipient := []usecases.Recipient{{PublicKey: resp.Key.PublicKey, Fingerprint: resp.Key.Fingerprint}}

	// --- zero recipients ---
	if _, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{FilePath: testFile, Recipients: []usecases.Recipient{}}); !errors.Is(err, entities.ErrNoRecipients) {
		t.Errorf("0 recipients: want ErrNoRecipients, got %v", err)
	}

	// --- 17 recipients (> soft cap) ---
	many := make([]usecases.Recipient, 17)
	for i := range many {
		r, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{Type: "x25519", Alias: fmt.Sprintf("overflow-%d", i), Passphrase: kp})
		if err != nil {
			t.Fatal(err)
		}
		many[i] = usecases.Recipient{PublicKey: r.Key.PublicKey, Fingerprint: r.Key.Fingerprint}
	}
	if _, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{FilePath: testFile, Recipients: many}); !errors.Is(err, entities.ErrTooManyRecipients) {
		t.Errorf("17 recipients: want ErrTooManyRecipients, got %v", err)
	}

	// --- corrupted recipient block must error, not panic ---
	// Encrypt a valid 1-recipient file, then truncate/corrupt a block's wrapped_cek.
	if _, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{FilePath: testFile, Recipients: oneRecipient}); err != nil {
		t.Fatal(err)
	}
	encPath := testFile + ".mdstn"
	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), raw...)
	// Corrupt the first wrapped_cek payload: locate a stable base64-ish substring
	// deep in the header and flip bytes far from structural fields. Simplest
	// robust approach: flip bytes in the middle of the header JSON.
	corrupt[len(corrupt)/2] ^= 0xFF
	corruptPath := filepath.Join(tmpDir, "corrupt.mdstn")
	if err := os.WriteFile(corruptPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decrypt panicked on corrupted header: %v", r)
			}
		}()
		if _, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{FilePath: corruptPath, OutputPath: filepath.Join(tmpDir, "out.bin")}); err == nil {
			t.Fatal("decrypt of corrupted header unexpectedly succeeded")
		}
	}()
}
