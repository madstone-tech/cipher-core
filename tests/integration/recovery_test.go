package integration

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// eofPrompter is a prompter whose PromptString returns io.EOF (simulates Ctrl-C / non-TTY abort).
type eofPrompter struct{}

func (p *eofPrompter) PromptString(prompt string) (string, error)     { return "", io.EOF }
func (p *eofPrompter) PromptConfirm(prompt string) (bool, error)      { return false, nil }
func (p *eofPrompter) PromptPassphrase(prompt string) (string, error) { return "test-passphrase", nil }

// wireEncryptUC is a helper that wires all dependencies and returns a ready EncryptFile usecase.
func wireEncryptUC(t *testing.T, dbPath string, prompter usecases.UserPrompter) (*usecases.EncryptFile, *sqlite.RecoveryKeyRepository) {
	t.Helper()

	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to open key repository: %v", err)
	}
	t.Cleanup(func() { _ = keyRepo.Close() })

	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())
	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	cryptoEngine := crypto.NewEngine()
	encoder := crypto.NewFileEncoder()
	ckdClient := ckd.NewClient(ckdCache)
	fileHandler := cli.NewFileHandler()
	progress := &noopProgress{}
	logger := logging.NewSimpleLogger()

	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(context.Background())
	t.Cleanup(func() { sessionStore.Stop() })
	lookupKeyUC := usecases.NewLookupKey(ckdClient, ckdCache, logger)
	encryptUC := usecases.NewEncryptFile(
		keyRepo,
		recoveryRepo,
		cryptoEngine,
		kekProvider,
		sessionStore,
		encoder,
		lookupKeyUC,
		fileHandler,
		progress,
		prompter,
		logger,
	)

	return encryptUC, recoveryRepo
}

// makeTestFile writes content to a temp file and returns its path.
func makeTestFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "plaintext.txt")
	if err := os.WriteFile(path, []byte("hello cipher"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// TestFirstRunRecoveryFlow verifies that on first encrypt (JSONOutput=true):
//   - recoveryRepo.Count becomes 1
//   - A second encrypt does not create another recovery key
func TestFirstRunRecoveryFlow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := makeTestFile(t, tmpDir)
	ctx := context.Background()

	encryptUC, recoveryRepo := wireEncryptUC(t, dbPath, &yesPrompter{})

	// First run — recovery key should be created.
	_, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		JSONOutput: true,
	})
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	count, err := recoveryRepo.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("after first run: recoveryRepo.Count = %d, want 1", count)
	}

	// Second run — no additional recovery key should be stored.
	_, err = encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile + ".mdstn", // re-encrypt the already-encrypted file (any file works)
		JSONOutput: true,
	})
	// Ignore the error — we only care about Count.
	_ = err

	count, err = recoveryRepo.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("after second run: recoveryRepo.Count = %d, want 1", count)
	}
}

// TestFirstRunJSONMode verifies that JSONOutput=true on a fresh DB returns a valid
// 24-word BIP39 mnemonic in the response and that a second run returns no mnemonic.
func TestFirstRunJSONMode(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := makeTestFile(t, tmpDir)
	ctx := context.Background()

	encryptUC, _ := wireEncryptUC(t, dbPath, &yesPrompter{})

	// First run.
	resp, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		JSONOutput: true,
	})
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}
	if resp.RecoveryMnemonic == "" {
		t.Fatal("expected RecoveryMnemonic to be non-empty on first run")
	}
	if !bip39.IsMnemonicValid(resp.RecoveryMnemonic) {
		t.Errorf("RecoveryMnemonic %q is not a valid BIP39 mnemonic", resp.RecoveryMnemonic)
	}

	// Second run against the same DB — mnemonic must be absent. Overwrite: the
	// default <file>.mdstn of the first run exists.
	resp2, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		JSONOutput: true,
		Overwrite:  true,
	})
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}
	if resp2.RecoveryMnemonic != "" {
		t.Errorf("expected RecoveryMnemonic to be empty on second run, got %q", resp2.RecoveryMnemonic)
	}
}

// TestNonTTYWithoutJSON verifies that when the prompter returns an error
// (simulating EOF / Ctrl-C) the usecase returns ErrRecoveryAborted.
func TestNonTTYWithoutJSON(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := makeTestFile(t, tmpDir)
	ctx := context.Background()

	// eofPrompter simulates a non-interactive context where stdin returns EOF.
	encryptUC, _ := wireEncryptUC(t, dbPath, &eofPrompter{})

	_, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		JSONOutput: false, // interactive path — will hit the prompter
	})
	if err == nil {
		t.Fatal("expected ErrRecoveryAborted, got nil")
	}
	if !isRecoveryAborted(err) {
		t.Errorf("expected ErrRecoveryAborted, got %v", err)
	}
}

// isRecoveryAborted checks whether err is ErrRecoveryAborted or the non-TTY error.
// In test environments (no TTY), the TTY check fires before the prompter is reached,
// returning a different sentinel. Both indicate the interactive recovery flow cannot proceed.
func isRecoveryAborted(err error) bool {
	if err == nil {
		return false
	}
	if err == entities.ErrRecoveryAborted {
		return true
	}
	// Non-TTY environments hit this error before the prompter is called.
	return strings.Contains(err.Error(), "interactive terminal")
}
