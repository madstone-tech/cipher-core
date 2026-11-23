package usecases

import (
	"bytes"
	"context"
	"errors"
	"testing"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
)

// multiPrompter returns a sequence of responses for PromptString and
// PromptPassphrase calls, enabling multi-step prompt testing.
type multiPrompter struct {
	strings     []string
	passphrases []string
	sIdx        int
	pIdx        int
}

func (m *multiPrompter) PromptString(_ string) (string, error) {
	s := m.strings[m.sIdx]
	m.sIdx++
	return s, nil
}

func (m *multiPrompter) PromptPassphrase(_ string) (string, error) {
	p := m.passphrases[m.pIdx]
	m.pIdx++
	return p, nil
}

func (m *multiPrompter) PromptConfirm(_ string) (bool, error) { return true, nil }

// fakeMnemonicDeriver returns a known deterministic mnemonic-derived keypair
// so tests do not depend on BIP39 entropy.
func fakeMnemonicDeriver(mnemonic string) (publicKey, privateKey []byte, err error) {
	return cryptoadapter.DeriveX25519FromMnemonic(mnemonic)
}

// knownMnemonic is a valid 24-word BIP39 mnemonic used across recovery tests.
// Using a fixed phrase means the derived key is deterministic and verifiable.
const knownMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// TestRecoverFromMnemonic_WrapsAndStores verifies that RecoverFromMnemonic:
//   - stores the key wrapped (Argon2idSalt set, WrappedPrivateKey non-empty)
//   - does NOT store the raw private scalar
//   - the key passphrase correctly unwraps it to the derived scalar
func TestRecoverFromMnemonic_WrapsAndStores(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()

	prompter := &multiPrompter{
		strings:     []string{knownMnemonic},
		passphrases: []string{"my-key-passphrase"},
	}

	uc := NewRecoverKey(
		kekProvider,
		repo,
		crypto,
		prompter,
		&fakeLogger{},
	)

	key, err := uc.RecoverFromMnemonic(context.Background(), fakeMnemonicDeriver)
	if err != nil {
		t.Fatalf("RecoverFromMnemonic: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	// Salt must be set (16 bytes).
	if len(key.Argon2idSalt) != 16 {
		t.Fatalf("Argon2idSalt length: got %d, want 16", len(key.Argon2idSalt))
	}

	// WrappedPrivateKey must be ciphertext, not the raw 32-byte scalar.
	// AES-256-GCM: 12-byte nonce + 32-byte ciphertext + 16-byte tag = 60 bytes.
	if len(key.WrappedPrivateKey) < 50 {
		t.Fatalf("WrappedPrivateKey too short (%d bytes) — likely raw key, not wrapped", len(key.WrappedPrivateKey))
	}

	// Exactly one Create call, no Update.
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 repo.Create call, got %d", repo.createCalls)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("expected 0 repo.Update calls for new key, got %d", repo.updateCalls)
	}

	// The passphrase must unwrap to the derived private scalar.
	kek, err := kekProvider.DeriveKEK("my-key-passphrase", key.Argon2idSalt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	unwrapped, err := kekProvider.UnwrapKey(key.WrappedPrivateKey, kek, key.ID)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if len(unwrapped) != 32 {
		t.Fatalf("unwrapped key length: got %d, want 32", len(unwrapped))
	}

	// The unwrapped scalar must reproduce the expected public key.
	_, expectedPrivate, err := fakeMnemonicDeriver(knownMnemonic)
	if err != nil {
		t.Fatalf("fakeMnemonicDeriver: %v", err)
	}
	for i, b := range expectedPrivate {
		if unwrapped[i] != b {
			t.Fatalf("unwrapped private key does not match derived scalar at byte %d", i)
		}
	}
}

// TestRecoverFromMnemonic_ReWrapCallsUpdate verifies that recovering the same
// mnemonic a second time with a different passphrase calls Update (re-wrap)
// exactly once and does NOT call Create again. The new passphrase must unwrap
// the key; the old passphrase must not.
func TestRecoverFromMnemonic_ReWrapCallsUpdate(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()

	// First recovery: store the key with "passphrase-one".
	prompter1 := &multiPrompter{
		strings:     []string{knownMnemonic},
		passphrases: []string{"passphrase-one"},
	}
	uc1 := NewRecoverKey(kekProvider, repo, crypto, prompter1, &fakeLogger{})
	_, err := uc1.RecoverFromMnemonic(context.Background(), fakeMnemonicDeriver)
	if err != nil {
		t.Fatalf("first RecoverFromMnemonic: %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("after first recovery: expected 1 Create call, got %d", repo.createCalls)
	}

	// Second recovery: same mnemonic, different passphrase "passphrase-two".
	prompter2 := &multiPrompter{
		strings:     []string{knownMnemonic},
		passphrases: []string{"passphrase-two"},
	}
	uc2 := NewRecoverKey(kekProvider, repo, crypto, prompter2, &fakeLogger{})
	key2, err := uc2.RecoverFromMnemonic(context.Background(), fakeMnemonicDeriver)
	if err != nil {
		t.Fatalf("second RecoverFromMnemonic: %v", err)
	}
	if key2 == nil {
		t.Fatal("second recovery: expected non-nil key")
	}

	// Create must still be exactly 1 (no second create).
	if repo.createCalls != 1 {
		t.Fatalf("after second recovery: expected still 1 Create call, got %d", repo.createCalls)
	}
	// Update must have been called exactly once.
	if repo.updateCalls != 1 {
		t.Fatalf("after second recovery: expected 1 Update call, got %d", repo.updateCalls)
	}

	// The new passphrase must unwrap the key.
	kek2, err := kekProvider.DeriveKEK("passphrase-two", key2.Argon2idSalt)
	if err != nil {
		t.Fatalf("DeriveKEK for passphrase-two: %v", err)
	}
	unwrapped2, err := kekProvider.UnwrapKey(key2.WrappedPrivateKey, kek2, key2.ID)
	if err != nil {
		t.Fatalf("UnwrapKey with passphrase-two: %v", err)
	}
	if len(unwrapped2) != 32 {
		t.Fatalf("unwrapped key length: got %d, want 32", len(unwrapped2))
	}

	// The old passphrase must NOT unwrap the updated key.
	kek1, err := kekProvider.DeriveKEK("passphrase-one", key2.Argon2idSalt)
	if err != nil {
		t.Fatalf("DeriveKEK for passphrase-one: %v", err)
	}
	_, err = kekProvider.UnwrapKey(key2.WrappedPrivateKey, kek1, key2.ID)
	if err == nil {
		t.Fatal("old passphrase must not unwrap the re-wrapped key")
	}
}

// TestRecoverFromMnemonicWith_IsHeadless verifies the defining property of the
// headless variant: it completes without a prompter. The use case is
// constructed with a nil prompter, so any attempt to gather input
// interactively would panic rather than silently fall back.
func TestRecoverFromMnemonicWith_IsHeadless(t *testing.T) {
	repo := &fakeKeyRepo{}
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()

	uc := NewRecoverKey(
		kekProvider,
		repo,
		cryptoadapter.NewEngine(),
		nil, // no prompter: the headless path must never reach for one
		&fakeLogger{},
	)

	key, err := uc.RecoverFromMnemonicWith(
		context.Background(),
		knownMnemonic,
		"my-key-passphrase",
		fakeMnemonicDeriver,
	)
	if err != nil {
		t.Fatalf("RecoverFromMnemonicWith: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	if len(key.Argon2idSalt) != 16 {
		t.Fatalf("Argon2idSalt length: got %d, want 16", len(key.Argon2idSalt))
	}
	if len(key.WrappedPrivateKey) < 50 {
		t.Fatalf("WrappedPrivateKey too short (%d bytes) — likely raw key, not wrapped", len(key.WrappedPrivateKey))
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 repo.Create call, got %d", repo.createCalls)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("expected 0 repo.Update calls for new key, got %d", repo.updateCalls)
	}

	// The supplied passphrase must unwrap to the derived private scalar.
	kek, err := kekProvider.DeriveKEK("my-key-passphrase", key.Argon2idSalt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	unwrapped, err := kekProvider.UnwrapKey(key.WrappedPrivateKey, kek, key.ID)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	_, expectedPrivate, err := fakeMnemonicDeriver(knownMnemonic)
	if err != nil {
		t.Fatalf("fakeMnemonicDeriver: %v", err)
	}
	if !bytes.Equal(unwrapped, expectedPrivate) {
		t.Fatal("unwrapped private key does not match derived scalar")
	}
}

// TestRecoverFromMnemonicWith_MatchesInteractive verifies that the headless and
// interactive variants are equivalent: the same mnemonic and passphrase must
// yield the same identity. Salts are random per call, so the invariant checked
// is the derived public key and fingerprint, not the wrapped bytes.
func TestRecoverFromMnemonicWith_MatchesInteractive(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()

	newUC := func(prompter UserPrompter) *RecoverKey {
		return NewRecoverKey(
			kekProvider,
			&fakeKeyRepo{},
			cryptoadapter.NewEngine(),
			prompter,
			&fakeLogger{},
		)
	}

	interactive, err := newUC(&multiPrompter{
		strings:     []string{knownMnemonic},
		passphrases: []string{"my-key-passphrase"},
	}).RecoverFromMnemonic(context.Background(), fakeMnemonicDeriver)
	if err != nil {
		t.Fatalf("RecoverFromMnemonic: %v", err)
	}

	headless, err := newUC(nil).RecoverFromMnemonicWith(
		context.Background(),
		knownMnemonic,
		"my-key-passphrase",
		fakeMnemonicDeriver,
	)
	if err != nil {
		t.Fatalf("RecoverFromMnemonicWith: %v", err)
	}

	if !bytes.Equal(headless.PublicKey, interactive.PublicKey) {
		t.Errorf("PublicKey mismatch:\n headless    = %v\n interactive = %v",
			headless.PublicKey, interactive.PublicKey)
	}
	if headless.Fingerprint != interactive.Fingerprint {
		t.Errorf("Fingerprint mismatch:\n headless    = %v\n interactive = %v",
			headless.Fingerprint, interactive.Fingerprint)
	}
}

// TestRecoverFromMnemonicWith_RejectsBadInput verifies that the headless
// variant validates its arguments instead of relying on a prompter to have
// gathered something sensible, and that a deriver failure propagates rather
// than producing a key.
func TestRecoverFromMnemonicWith_RejectsBadInput(t *testing.T) {
	derivErr := errors.New("boom")
	failingDeriver := func(string) (publicKey, privateKey []byte, err error) {
		return nil, nil, derivErr
	}

	tests := []struct {
		name       string
		mnemonic   string
		passphrase string
		deriver    MnemonicDeriver
	}{
		{"empty mnemonic", "", "my-key-passphrase", fakeMnemonicDeriver},
		{"empty passphrase", knownMnemonic, "", fakeMnemonicDeriver},
		{"deriver failure", knownMnemonic, "my-key-passphrase", failingDeriver},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeKeyRepo{}
			uc := NewRecoverKey(
				cryptoadapter.NewArgon2idKEKProvider(),
				repo,
				cryptoadapter.NewEngine(),
				nil,
				&fakeLogger{},
			)

			key, err := uc.RecoverFromMnemonicWith(
				context.Background(), tt.mnemonic, tt.passphrase, tt.deriver,
			)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if key != nil {
				t.Errorf("expected nil key on error, got %+v", key)
			}
			if repo.createCalls != 0 || repo.updateCalls != 0 {
				t.Errorf("expected no repository writes on error, got %d create / %d update",
					repo.createCalls, repo.updateCalls)
			}
		})
	}
}
