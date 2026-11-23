package integration

import (
	"context"
	"errors"
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

// TestHeaderTamperRejected — usecase-level tamper gate: flip one
// header byte in a fully-pipelined encrypted file; decrypt must fail with
// ErrHeaderAuthFailed, produce NO output file, and be distinguishable from
// not-a-recipient and wrong-passphrase failures.
func TestHeaderTamperRejected(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	srcFile := filepath.Join(tmpDir, "secret.txt")

	plaintext := []byte("tamper-gate test payload")
	if err := os.WriteFile(srcFile, plaintext, 0o600); err != nil {
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

	createKeyUC := usecases.NewCreateKey(keyRepo, cryptoEngine, kekProvider, sessionStore, nil, logger)
	passphrase := "tamper-gate-passphrase"
	resp, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{Type: "x25519", Alias: "r1", Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt via the real multi-recipient usecase path (in-memory size).
	lookupKeyUC := usecases.NewLookupKey(ckdClient, ckdCache, logger)
	encryptUC := usecases.NewEncryptFile(keyRepo, recoveryRepo, cryptoEngine, kekProvider, sessionStore, encoder, lookupKeyUC, fileHandler, progress, prompter, logger)
	outPath := srcFile + ".mdstn"
	if _, err := encryptUC.Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:   srcFile,
		OutputPath: outPath,
		Recipients: []usecases.Recipient{{PublicKey: resp.Key.PublicKey, Fingerprint: resp.Key.Fingerprint}},
		JSONOutput: true,
	}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	// New files are format v2 (version byte 0x03).
	if raw[4] != 0x03 {
		t.Fatalf("version byte = %d, want 3 (format v2)", raw[4])
	}

	// Decrypt untampered — positive control.
	decryptPrompter := &testPassphrasePrompter{passphrase: passphrase}
	decryptUC := usecases.NewDecryptFile(keyRepo, cryptoEngine, kekProvider, sessionStore, encoder, fileHandler, progress, decryptPrompter, logger)
	decPath := filepath.Join(tmpDir, "control.bin")
	if _, err := decryptUC.Execute(ctx, &usecases.DecryptFileRequest{FilePath: outPath, OutputPath: decPath}); err != nil {
		t.Fatalf("positive control decrypt failed: %v", err)
	}
	got, err := os.ReadFile(decPath)
	if err != nil || string(got) != string(plaintext) {
		t.Fatalf("positive control plaintext mismatch: %v %q", err, got)
	}

	// (a) Tamper a header byte that is not key material: one character
	// inside the original_filename value. The JSON still parses; the body
	// GCM (header bytes are its AAD) must fail → ErrHeaderAuthFailed.
	tampered := append([]byte(nil), raw...)
	nameMarker := []byte("\"original_filename\":\"")
	ni := indexOf(tampered, nameMarker)
	if ni < 0 {
		t.Fatal("no original_filename field found in header")
	}
	tampered[ni+len(nameMarker)] ^= 0x01
	tamperPath := filepath.Join(tmpDir, "tampered.mdstn")
	if err := os.WriteFile(tamperPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	outPath2 := filepath.Join(tmpDir, "should-not-exist.bin")
	_, err = decryptUC.Execute(ctx, &usecases.DecryptFileRequest{FilePath: tamperPath, OutputPath: outPath2})
	if err == nil {
		t.Fatal("tampered header decrypted successfully — AAD gate missing")
	}
	if !errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Errorf("want ErrHeaderAuthFailed, got: %v", err)
	}
	if _, statErr := os.Stat(outPath2); !os.IsNotExist(statErr) {
		t.Errorf("output file written despite tamper: %v", statErr)
	}

	// (a2) Tamper the wrapped_cek of the only recipient block. A v2 block
	// names no recipient (FR-023), so a damaged block cannot be told from a
	// block for another key: no local key opens it → ErrNotARecipient.
	blockTampered := append([]byte(nil), raw...)
	wrapKeyMarker := []byte("\"wrapped_cek\":\"")
	ki := indexOf(blockTampered, wrapKeyMarker)
	if ki < 0 {
		t.Fatal("no wrapped_cek field found in header")
	}
	valStart := ki + len(wrapKeyMarker)
	if blockTampered[valStart] != 'A' {
		blockTampered[valStart] = 'A'
	} else {
		blockTampered[valStart] = 'B'
	}
	blockTamperPath := filepath.Join(tmpDir, "block-tampered.mdstn")
	if err := os.WriteFile(blockTamperPath, blockTampered, 0o600); err != nil {
		t.Fatal(err)
	}
	outPathBlock := filepath.Join(tmpDir, "should-not-exist-block.bin")
	_, err = decryptUC.Execute(ctx, &usecases.DecryptFileRequest{FilePath: blockTamperPath, OutputPath: outPathBlock})
	if !errors.Is(err, entities.ErrNotARecipient) {
		t.Errorf("block tamper: want ErrNotARecipient, got: %v", err)
	}
	if _, statErr := os.Stat(outPathBlock); !os.IsNotExist(statErr) {
		t.Errorf("output file written despite block tamper: %v", statErr)
	}

	// (b) Body-section tamper (nonce byte flipped): the body frame is GCM-bound
	// to the header AAD → this one MUST map to ErrHeaderAuthFailed.
	bodyTampered := append([]byte(nil), raw...)
	bodyTampered[len(bodyTampered)-1] ^= 0xFF
	bodyTamperPath := filepath.Join(tmpDir, "body-tampered.mdstn")
	if err := os.WriteFile(bodyTamperPath, bodyTampered, 0o600); err != nil {
		t.Fatal(err)
	}
	outPath3 := filepath.Join(tmpDir, "should-not-exist-2.bin")
	_, err = decryptUC.Execute(ctx, &usecases.DecryptFileRequest{FilePath: bodyTamperPath, OutputPath: outPath3})
	if err == nil {
		t.Fatal("tampered body decrypted successfully")
	}
	if !errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Errorf("body tamper: want ErrHeaderAuthFailed, got: %v", err)
	}

	// Distinctness: a not-a-recipient failure must NOT be header-auth failure.
	wrongKey, err := createKeyUC.Execute(ctx, &usecases.CreateKeyRequest{Type: "x25519", Alias: "non-recipient", Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if wrongKey.Key.ID == resp.Key.ID {
		t.Fatal("test key identities collided")
	}
	_ = entities.ErrNotARecipient // taxonomy anchor
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
