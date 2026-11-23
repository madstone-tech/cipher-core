package integration

import (
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// TestStreamingRoundTrip10MB writes 10 MiB of random bytes to a temp file,
// encrypts it via EncryptFile.Execute (which routes ≥ 1 MiB through EncryptStream),
// decrypts it via DecryptFile.Execute, and asserts the output matches the input exactly.
func TestStreamingRoundTrip10MB(t *testing.T) {
	const fileSize = 10 << 20 // 10 MiB

	tmpDir, err := os.MkdirTemp("", "cipher-stream-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := filepath.Join(tmpDir, "bigfile.bin")
	encryptedFile := testFile + ".mdstn"
	decryptedFile := testFile + ".dec"

	// Write 10 MiB of random bytes.
	randomData := make([]byte, fileSize)
	if _, err := io.ReadFull(rand.Reader, randomData); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	if err := os.WriteFile(testFile, randomData, 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	ctx := context.Background()

	// Wire dependencies.
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to create key repository: %v", err)
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

	// Encrypt.
	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(ctx)
	defer sessionStore.Stop()
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

	encResp, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		JSONOutput: true, // skip interactive prompt in tests
	})
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if encResp.OutputPath != encryptedFile {
		t.Errorf("expected output path %s, got %s", encryptedFile, encResp.OutputPath)
	}

	// Decrypt (reuse kekProvider and sessionStore from encrypt setup).
	decryptPrompter := &noopPrompter{}
	decryptUC := usecases.NewDecryptFile(
		keyRepo,
		cryptoEngine,
		kekProvider,
		sessionStore,
		encoder,
		fileHandler,
		progress,
		decryptPrompter,
		logger,
	)

	decResp, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:   encryptedFile,
		OutputPath: decryptedFile,
	})
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if decResp.OutputPath != decryptedFile {
		t.Errorf("expected output path %s, got %s", decryptedFile, decResp.OutputPath)
	}

	// Compare.
	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}
	if len(decryptedData) != fileSize {
		t.Errorf("decrypted size = %d, want %d", len(decryptedData), fileSize)
	}

	for i := range randomData {
		if randomData[i] != decryptedData[i] {
			t.Errorf("data mismatch at byte %d", i)
			break
		}
	}
}
