package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "cipher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := filepath.Join(tmpDir, "test.txt")
	encryptedFile := testFile + ".mdstn"

	// Create test file
	testData := []byte("This is a secret message for integration testing.")
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()

	// Wire dependencies
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
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

	// Test encryption
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
		t.Fatalf("Encryption failed: %v", err)
	}

	if encResp.OutputPath != encryptedFile {
		t.Errorf("Expected output path %s, got %s", encryptedFile, encResp.OutputPath)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatal("Encrypted file was not created")
	}

	// Remove original file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to remove original file: %v", err)
	}

	// Test decryption (reuse kekProvider and sessionStore from encrypt setup)
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
		OutputPath: testFile,
	})
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decResp.OutputPath != testFile {
		t.Errorf("Expected output path %s, got %s", testFile, decResp.OutputPath)
	}

	// Verify decrypted content
	decryptedData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted content doesn't match.\nExpected: %s\nGot: %s", testData, decryptedData)
	}
}

func TestPassphraseEncryptDecrypt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cipher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := filepath.Join(tmpDir, "secret.txt")
	encryptedFile := testFile + ".mdstn"

	testData := []byte("Secret data with passphrase")
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	passphrase := "test-passphrase-123"

	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
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

	// Encrypt with passphrase (passphrase path does not trigger recovery flow)
	kekProvider2 := crypto.NewArgon2idKEKProvider()
	sessionStore2 := crypto.NewInMemorySessionStore(ctx)
	defer sessionStore2.Stop()
	lookupKeyUC2 := usecases.NewLookupKey(ckdClient, ckdCache, logger)
	encryptUC := usecases.NewEncryptFile(
		keyRepo,
		recoveryRepo,
		cryptoEngine,
		kekProvider2,
		sessionStore2,
		encoder,
		lookupKeyUC2,
		fileHandler,
		progress,
		prompter,
		logger,
	)

	_, err = encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Remove original
	os.Remove(testFile)

	// Decrypt with passphrase (reuse kekProvider2 and sessionStore2 from encrypt setup)
	decryptPrompter := &noopPrompter{}
	decryptUC := usecases.NewDecryptFile(
		keyRepo,
		cryptoEngine,
		kekProvider2,
		sessionStore2,
		encoder,
		fileHandler,
		progress,
		decryptPrompter,
		logger,
	)

	_, err = decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:   encryptedFile,
		Passphrase: passphrase,
		OutputPath: testFile,
	})
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	decryptedData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted content doesn't match")
	}
}

// noopProgress is a no-op progress reporter for testing
type noopProgress struct{}

func (p *noopProgress) ReportProgress(message string, percent int) {}
func (p *noopProgress) ReportError(err error)                      {}
func (p *noopProgress) ReportSuccess(message string)               {}

// noopPrompter is a no-op prompter for testing (used in decryption path)
type noopPrompter struct{}

func (p *noopPrompter) PromptString(prompt string) (string, error)     { return "", nil }
func (p *noopPrompter) PromptConfirm(prompt string) (bool, error)      { return false, nil }
func (p *noopPrompter) PromptPassphrase(prompt string) (string, error) { return "test-passphrase", nil }

// yesPrompter answers "yes" to all PromptString calls (used for recovery confirmation)
type yesPrompter struct{}

func (p *yesPrompter) PromptString(prompt string) (string, error)     { return "yes", nil }
func (p *yesPrompter) PromptConfirm(prompt string) (bool, error)      { return true, nil }
func (p *yesPrompter) PromptPassphrase(prompt string) (string, error) { return "test-passphrase", nil }

func TestMultiRecipientEncryptDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	testFile := filepath.Join(tmpDir, "test.txt")

	testData := []byte("This is a secret message for multi-recipient integration testing.")
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()

	// Wire dependencies
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create key repository: %v", err)
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

	// Create two identity keys (recipients)
	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	passphrase := "test-passphrase-for-key-creation"

	createResp1, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
		Type:       "x25519",
		Alias:      "recipient-one",
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Failed to create key 1: %v", err)
	}
	key1 := createResp1.Key

	createResp2, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
		Type:       "x25519",
		Alias:      "recipient-two",
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Failed to create key 2: %v", err)
	}
	key2 := createResp2.Key

	// Create a third key (not a recipient, for negative testing)
	createResp3, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
		Type:       "x25519",
		Alias:      "not-a-recipient",
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Failed to create key 3: %v", err)
	}
	key3 := createResp3.Key
	_ = key3.Fingerprint // used in negative test below

	// Encrypt to both recipients
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

	recipients := []usecases.Recipient{
		{PublicKey: key1.PublicKey, Fingerprint: key1.Fingerprint},
		{PublicKey: key2.PublicKey, Fingerprint: key2.Fingerprint},
	}

	encryptedFile := testFile + ".mdstn"
	encResp, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		Recipients: recipients,
		JSONOutput: true,
	})
	if err != nil {
		t.Fatalf("Multi-recipient encryption failed: %v", err)
	}

	if encResp.OutputPath != encryptedFile {
		t.Errorf("Expected output path %s, got %s", encryptedFile, encResp.OutputPath)
	}

	if encResp.Method != entities.MethodX25519 {
		t.Errorf("Expected method %s, got %s", entities.MethodX25519, encResp.Method)
	}

	// Remove original file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to remove original file: %v", err)
	}

	// Test decryption with recipient 1's key
	decryptPrompter := &testPassphrasePrompter{passphrase: passphrase}
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

	decResp1, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           encryptedFile,
		OutputPath:         testFile,
		RecoveryPassphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Decryption with recipient 1 key failed: %v", err)
	}
	if decResp1.OutputPath != testFile {
		t.Errorf("Expected output path %s, got %s", testFile, decResp1.OutputPath)
	}
	decryptedData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted content doesn't match.\nExpected: %s\nGot: %s", testData, decryptedData)
	}
	os.Remove(testFile)

	// Test decryption with recipient 2's key (by temporarily removing key1 from DB)
	// Actually, both keys are in the DB, so decryption should still succeed with key2
	// The decrypt usecase scans all available keys and finds a matching recipient block
	decResp2, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           encryptedFile,
		OutputPath:         testFile,
		RecoveryPassphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Decryption with recipient 2 key failed: %v", err)
	}
	if decResp2.OutputPath != testFile {
		t.Errorf("Expected output path %s, got %s", testFile, decResp2.OutputPath)
	}
	decryptedData, err = os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted content doesn't match.\nExpected: %s\nGot: %s", testData, decryptedData)
	}
	os.Remove(testFile)

	// Negative test: decrypt with key3 (not a recipient) — should fail
	// First, delete key1 and key2 so only key3 remains
	if err := keyRepo.Delete(ctx, key1.ID); err != nil {
		t.Fatalf("Failed to delete key1: %v", err)
	}
	if err := keyRepo.Delete(ctx, key2.ID); err != nil {
		t.Fatalf("Failed to delete key2: %v", err)
	}

	_, err = decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           encryptedFile,
		OutputPath:         testFile,
		RecoveryPassphrase: passphrase,
	})
	if err == nil {
		t.Fatal("Expected decryption to fail with non-recipient key, but it succeeded")
	}
	if !errors.Is(err, entities.ErrNotARecipient) {
		t.Errorf("Expected ErrNotARecipient, got: %v", err)
	}
}

// testPassphrasePrompter answers with a configurable passphrase
type testPassphrasePrompter struct {
	passphrase string
}

func (p *testPassphrasePrompter) PromptString(prompt string) (string, error) { return "yes", nil }
func (p *testPassphrasePrompter) PromptConfirm(prompt string) (bool, error)  { return true, nil }
func (p *testPassphrasePrompter) PromptPassphrase(prompt string) (string, error) {
	return p.passphrase, nil
}

// BenchmarkMultiRecipientEncrypt benchmarks encrypting a file to 4 recipients.
func BenchmarkMultiRecipientEncrypt(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	testFile := filepath.Join(tmpDir, "bench.txt")

	testData := make([]byte, 1024*1024) // 1 MiB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		b.Fatalf("Failed to create key repository: %v", err)
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

	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	passphrase := "bench-passphrase"

	recipients := make([]usecases.Recipient, 0, 4)
	for i := 0; i < 4; i++ {
		resp, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
			Type:       "x25519",
			Alias:      fmt.Sprintf("bench-recipient-%d", i),
			Passphrase: passphrase,
		})
		if err != nil {
			b.Fatalf("Failed to create key %d: %v", i, err)
		}
		recipients = append(recipients, usecases.Recipient{
			PublicKey:   resp.Key.PublicKey,
			Fingerprint: resp.Key.Fingerprint,
		})
	}

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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
			FilePath:   testFile,
			Recipients: recipients,
			JSONOutput: true,
		})
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkMultiRecipientDecrypt benchmarks decrypting a multi-recipient file.
func BenchmarkMultiRecipientDecrypt(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	testFile := filepath.Join(tmpDir, "bench.txt")
	encryptedFile := testFile + ".mdstn"

	testData := make([]byte, 1024*1024) // 1 MiB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		b.Fatalf("Failed to create key repository: %v", err)
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

	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	passphrase := "bench-passphrase"

	resp, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
		Type:       "x25519",
		Alias:      "bench-recipient",
		Passphrase: passphrase,
	})
	if err != nil {
		b.Fatalf("Failed to create key: %v", err)
	}
	recipients := []usecases.Recipient{
		{PublicKey: resp.Key.PublicKey, Fingerprint: resp.Key.Fingerprint},
	}

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

	_, err = encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   testFile,
		Recipients: recipients,
		JSONOutput: true,
	})
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	decryptPrompter := &testPassphrasePrompter{passphrase: passphrase}
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{
			FilePath:           encryptedFile,
			OutputPath:         filepath.Join(tmpDir, fmt.Sprintf("out-%d.txt", i)),
			RecoveryPassphrase: passphrase,
		})
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkEncrypt16Recipients measures end-to-end through the EncryptFile
// usecase: a 1 MiB file encrypted to 16 recipients must complete in well under 5 s.
func BenchmarkEncrypt16Recipients(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench16.db")
	testFile := filepath.Join(tmpDir, "bench16.txt")

	testData := make([]byte, 1024*1024) // 1 MiB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, testData, 0o600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		b.Fatalf("Failed to create key repository: %v", err)
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

	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	passphrase := "bench16-passphrase"

	recipients := make([]usecases.Recipient, 0, 16)
	for i := 0; i < 16; i++ {
		resp, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{
			Type:       "x25519",
			Alias:      fmt.Sprintf("bench16-recipient-%d", i),
			Passphrase: passphrase,
		})
		if err != nil {
			b.Fatalf("Failed to create key %d: %v", i, err)
		}
		recipients = append(recipients, usecases.Recipient{
			PublicKey:   resp.Key.PublicKey,
			Fingerprint: resp.Key.Fingerprint,
		})
	}

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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
			FilePath:   testFile,
			Recipients: recipients,
			OutputPath: filepath.Join(tmpDir, fmt.Sprintf("bench16-out-%d.mdstn", i)),
			JSONOutput: true,
		}); err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}
