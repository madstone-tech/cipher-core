package usecases

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// buildEncryptedX25519File creates a .mdstn file encrypted for pubKey: one
// recipient block in the header; body [header_mac(32)][body_nonce(12)]
// [single frame] sealed with the payload key; header bytes are the body AAD.
func buildEncryptedX25519File(t *testing.T, crypto *cryptoadapter.Engine, encoder FileEncoder, pubKey []byte, plaintext []byte) []byte {
	t.Helper()
	cek, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}
	ephPub, wrapNonce, wrappedCEK, err := crypto.WrapCEK(cek, pubKey, []byte(entities.WrapCEKAAD))
	if err != nil {
		t.Fatalf("WrapCEK: %v", err)
	}

	encFile := &entities.EncryptedFile{
		Version: entities.FormatVersion,
		Method:  entities.MethodX25519,
		Chunked: false,
		Recipients: []entities.RecipientBlock{{
			EphemeralPubKey: base64.StdEncoding.EncodeToString(ephPub),
			Nonce:           base64.StdEncoding.EncodeToString(wrapNonce),
			WrappedCEK:      base64.StdEncoding.EncodeToString(wrappedCEK),
		}},
		OriginalFilename: "test.txt",
	}
	headerBytes, err := encoder.EncodeHeader(encFile)
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}

	headerMAC, err := crypto.HeaderMAC(cek, headerBytes)
	if err != nil {
		t.Fatalf("HeaderMAC: %v", err)
	}
	payloadKey, err := crypto.DerivePayloadKey(cek)
	if err != nil {
		t.Fatalf("DerivePayloadKey: %v", err)
	}
	ciphertext, bodyNonce, err := crypto.EncryptAES(plaintext, payloadKey, headerBytes)
	if err != nil {
		t.Fatalf("EncryptAES: %v", err)
	}

	out := make([]byte, 0, len(headerBytes)+len(headerMAC)+len(bodyNonce)+len(ciphertext))
	out = append(out, headerBytes...)
	out = append(out, headerMAC...)
	out = append(out, bodyNonce...)
	out = append(out, ciphertext...)
	return out
}

func TestDecryptFile_X25519RoundTrip_WrappedKey(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()
	prompter := &passphrasePrompter{passphrase: "test-passphrase-123"}

	// Create a wrapped key
	pubKey, privKey, err := cryptoEng.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair: %v", err)
	}

	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("test-passphrase-123", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()

	// Build encrypted file manually
	original := []byte("Hello, encrypted world!")
	fh.files["test.txt.mdstn"] = buildEncryptedX25519File(t, cryptoEng, encoder, pubKey, original)

	// Decrypt using the wrapped key — should prompt for passphrase
	decryptUC := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, prompter, &fakeLogger{})

	decResp, err := decryptUC.Execute(context.Background(), &DecryptFileRequest{
		FilePath: "test.txt.mdstn",
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// Verify round-trip
	decrypted, err := fh.ReadFile(decResp.OutputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, original)
	}

	// KEK should now be cached
	cachedKEK, _ := sessionStore.GetKEK(key.ID)
	if cachedKEK == nil {
		t.Fatal("KEK should be cached after decrypt")
	}
}

func TestDecryptFile_WrongPassphrase(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()
	prompter := &passphrasePrompter{passphrase: "wrong-passphrase"}

	pubKey, privKey, _ := cryptoEng.GenerateX25519Keypair()
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("correct-passphrase", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()
	fh.files["test.txt.mdstn"] = buildEncryptedX25519File(t, cryptoEng, encoder, pubKey, []byte("secret"))

	// Decrypt with wrong passphrase — should fail
	decryptUC := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, prompter, &fakeLogger{})
	_, err := decryptUC.Execute(context.Background(), &DecryptFileRequest{
		FilePath: "test.txt.mdstn",
	})
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestDecryptFile_CachedKEK_NoPrompt(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()

	pubKey, privKey, _ := cryptoEng.GenerateX25519Keypair()
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("test-passphrase", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()

	// Pre-cache the KEK
	_ = sessionStore.SetKEK(key.ID, kek, 30*time.Minute)

	fh.files["test.txt.mdstn"] = buildEncryptedX25519File(t, cryptoEng, encoder, pubKey, []byte("cached KEK test"))

	// Use a prompter that panics if called — proves we don't prompt
	panicPrompter := &panicOnPromptPrompter{}

	decryptUC := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, panicPrompter, &fakeLogger{})
	_, err := decryptUC.Execute(context.Background(), &DecryptFileRequest{
		FilePath: "test.txt.mdstn",
	})
	if err != nil {
		t.Fatalf("Decrypt with cached KEK: %v", err)
	}
}

func TestDecryptFile_WrongPassphraseDoesNotPoisonCache(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()

	pubKey, privKey, _ := cryptoEng.GenerateX25519Keypair()
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("correct-passphrase", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()
	fh.files["test.mdstn"] = buildEncryptedX25519File(t, cryptoEng, encoder, pubKey, []byte("secret"))

	// Attempt 1: wrong passphrase — should fail and NOT cache
	wrongPrompter := &passphrasePrompter{passphrase: "wrong-passphrase"}
	decryptUC := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, wrongPrompter, &fakeLogger{})
	_, err := decryptUC.Execute(context.Background(), &DecryptFileRequest{FilePath: "test.mdstn"})
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}

	// Verify no KEK cached
	cached, _ := sessionStore.GetKEK(key.ID)
	if cached != nil {
		t.Fatal("wrong passphrase should not leave a cached KEK")
	}

	// Attempt 2: correct passphrase — should succeed
	correctPrompter := &passphrasePrompter{passphrase: "correct-passphrase"}
	decryptUC2 := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, correctPrompter, &fakeLogger{})
	_, err = decryptUC2.Execute(context.Background(), &DecryptFileRequest{FilePath: "test.mdstn"})
	if err != nil {
		t.Fatalf("correct passphrase should succeed: %v", err)
	}
}

// TestResolvePrivateKey_MnemonicPath verifies that supplying a 24-word BIP39
// recovery phrase as the passphrase re-derives the private key directly,
// bypassing the KEK/Argon2id unwrap path entirely.
func TestResolvePrivateKey_MnemonicPath(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()

	// Generate a known mnemonic and derive the expected keypair.
	mnemonic, err := cryptoEng.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	pubKey, expectedPrivKey, err := cryptoEng.DeriveX25519FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("DeriveX25519FromMnemonic: %v", err)
	}

	// Build an identity key with the mnemonic-derived public key, wrapped with a
	// known passphrase — this wrapping is intentionally NOT used in the mnemonic path.
	privKey := expectedPrivKey
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("irrelevant-passphrase", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "mnemonic-test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()

	uc := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, &panicOnPromptPrompter{}, &fakeLogger{})

	gotPrivKey, cleanup, _, err := uc.resolvePrivateKey(context.Background(), key, mnemonic)
	if err != nil {
		t.Fatalf("resolvePrivateKey with mnemonic: %v", err)
	}
	defer cleanup()

	if len(gotPrivKey) != len(expectedPrivKey) {
		t.Fatalf("private key length mismatch: got %d, want %d", len(gotPrivKey), len(expectedPrivKey))
	}
	for i := range expectedPrivKey {
		if gotPrivKey[i] != expectedPrivKey[i] {
			t.Fatalf("private key mismatch at byte %d", i)
		}
	}

	// A valid phrase of ANOTHER key must not unlock this key.
	other, err := cryptoEng.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	if _, _, _, err := uc.resolvePrivateKey(context.Background(), key, other); err == nil {
		t.Fatal("a recovery phrase of another key unlocked this key")
	}
}

// TestResolvePrivateKey_PassphrasePath verifies the existing KEK-unwrap path
// still works when a passphrase (not a mnemonic) is supplied.
func TestResolvePrivateKey_PassphrasePath(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()

	pubKey, privKey, err := cryptoEng.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair: %v", err)
	}
	const pp = "correct-passphrase-xyz"
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK(pp, salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "passphrase-test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()

	uc := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, &panicOnPromptPrompter{}, &fakeLogger{})

	gotPrivKey, cleanup, _, err := uc.resolvePrivateKey(context.Background(), key, pp)
	if err != nil {
		t.Fatalf("resolvePrivateKey with passphrase: %v", err)
	}
	defer cleanup()

	if len(gotPrivKey) != len(privKey) {
		t.Fatalf("private key length mismatch: got %d, want %d", len(gotPrivKey), len(privKey))
	}
	for i := range privKey {
		if gotPrivKey[i] != privKey[i] {
			t.Fatalf("private key mismatch at byte %d", i)
		}
	}
}

// TestResolvePrivateKey_InvalidSecret verifies that a completely invalid string
// (neither a valid mnemonic nor a correct passphrase for the wrapped key)
// returns an error.
func TestResolvePrivateKey_InvalidSecret(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	cryptoEng := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	sessionStore := newFakeSessionStore()

	pubKey, privKey, err := cryptoEng.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair: %v", err)
	}
	salt, _ := kekProvider.GenerateSalt()
	kek, _ := kekProvider.DeriveKEK("the-real-passphrase", salt)
	fingerprint := cryptoEng.Hash(pubKey)
	wrappedPriv, _ := kekProvider.WrapKey(privKey, kek, fingerprint[:16])
	key := &entities.IdentityKey{
		ID:                fingerprint[:16],
		Type:              entities.KeyTypeX25519,
		Alias:             "invalid-test",
		Fingerprint:       fingerprint,
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		Argon2idSalt:      salt,
		StorageMode:       entities.StorageModeStandard,
		StorageBackend:    entities.StorageBackendSQLite,
	}

	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()

	uc := NewDecryptFile(repo, cryptoEng, kekProvider, sessionStore, encoder, fh, &fakeProgress{}, &panicOnPromptPrompter{}, &fakeLogger{})

	_, _, _, err = uc.resolvePrivateKey(context.Background(), key, "totally-wrong-secret")
	if err == nil {
		t.Fatal("expected error for invalid secret, got nil")
	}
}

// panicOnPromptPrompter panics if PromptPassphrase is called — used to verify
// that cached KEK skips the prompt.
type panicOnPromptPrompter struct{}

func (p *panicOnPromptPrompter) PromptString(_ string) (string, error) {
	panic("PromptString should not be called")
}

func (p *panicOnPromptPrompter) PromptConfirm(_ string) (bool, error) {
	panic("PromptConfirm should not be called")
}

func (p *panicOnPromptPrompter) PromptPassphrase(_ string) (string, error) {
	panic("PromptPassphrase should not be called — KEK should be cached")
}
