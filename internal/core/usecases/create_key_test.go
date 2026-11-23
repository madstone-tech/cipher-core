package usecases

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
)

// passphrasePrompter returns a fixed passphrase for testing.
type passphrasePrompter struct {
	passphrase string
}

func (p *passphrasePrompter) PromptString(_ string) (string, error)     { return p.passphrase, nil }
func (p *passphrasePrompter) PromptConfirm(_ string) (bool, error)      { return true, nil }
func (p *passphrasePrompter) PromptPassphrase(_ string) (string, error) { return p.passphrase, nil }

// fakeSessionStore is a minimal in-memory session store for testing.
type fakeSessionStore struct {
	entries map[string][]byte
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{entries: make(map[string][]byte)}
}

func (s *fakeSessionStore) SetKEK(keyID string, kek []byte, _ time.Duration) error {
	copied := make([]byte, len(kek))
	copy(copied, kek)
	s.entries[keyID] = copied
	return nil
}

func (s *fakeSessionStore) GetKEK(keyID string) ([]byte, error) {
	kek, ok := s.entries[keyID]
	if !ok {
		return nil, nil
	}
	// The port requires a defensive copy that the caller may zero.
	return append([]byte(nil), kek...), nil
}

func (s *fakeSessionStore) Clear() error {
	s.entries = make(map[string][]byte)
	return nil
}

func (s *fakeSessionStore) ClearKey(keyID string) error {
	delete(s.entries, keyID)
	return nil
}

func TestCreateKey_WrapsPrivateKey(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	sessionStore := newFakeSessionStore()
	prompter := &passphrasePrompter{passphrase: "test-passphrase-123"}

	uc := NewCreateKey(repo, crypto, kekProvider, sessionStore, prompter, &fakeLogger{})

	resp, err := uc.Execute(context.Background(), &CreateKeyRequest{
		Alias: "test-key",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	key := resp.Key

	// Argon2idSalt must be populated (16 bytes)
	if len(key.Argon2idSalt) != 16 {
		t.Fatalf("Argon2idSalt length: got %d, want 16", len(key.Argon2idSalt))
	}

	// WrappedPrivateKey must be ciphertext (longer than raw 32-byte X25519 key)
	// nonce(12) + ciphertext(32) + GCM tag(16) = 60 bytes
	if len(key.WrappedPrivateKey) < 50 {
		t.Fatalf("WrappedPrivateKey too short (%d bytes) — likely raw key, not wrapped", len(key.WrappedPrivateKey))
	}

	// Key should be stored in repo
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 repo.Create call, got %d", repo.createCalls)
	}

	// KEK should be cached in session store
	cachedKEK, _ := sessionStore.GetKEK(key.ID)
	if cachedKEK == nil {
		t.Fatal("KEK should be cached in session store after key creation")
	}

	// Verify we can unwrap the key with the same passphrase
	kek, err := kekProvider.DeriveKEK("test-passphrase-123", key.Argon2idSalt)
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
}

func TestCreateKey_EmptyPassphraseRejected(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	sessionStore := newFakeSessionStore()
	prompter := &passphrasePrompter{passphrase: ""}

	uc := NewCreateKey(repo, crypto, kekProvider, sessionStore, prompter, &fakeLogger{})

	_, err := uc.Execute(context.Background(), &CreateKeyRequest{
		Alias: "test-key",
	})
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestCreateKey_NilPrompterReturnsError(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	sessionStore := newFakeSessionStore()

	uc := NewCreateKey(repo, crypto, kekProvider, sessionStore, nil, &fakeLogger{})

	_, err := uc.Execute(context.Background(), &CreateKeyRequest{Alias: "test"})
	if err == nil {
		t.Fatal("expected error for nil prompter")
	}
}

func TestCreateKey_NilKEKProviderReturnsError(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	prompter := &passphrasePrompter{passphrase: "test"}

	uc := NewCreateKey(repo, crypto, nil, nil, prompter, &fakeLogger{})

	_, err := uc.Execute(context.Background(), &CreateKeyRequest{Alias: "test"})
	if err == nil {
		t.Fatal("expected error for nil KEKProvider/SessionStore")
	}
}

func TestCreateKey_DerivesMnemonicKey(t *testing.T) {
	repo := &fakeKeyRepo{}
	crypto := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	sessionStore := newFakeSessionStore()
	prompter := &passphrasePrompter{passphrase: "test-passphrase-123"}

	uc := NewCreateKey(repo, crypto, kekProvider, sessionStore, prompter, &fakeLogger{})

	resp, err := uc.Execute(context.Background(), &CreateKeyRequest{
		Alias: "mnemonic-key",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// resp.Mnemonic must be a non-empty 24-word string
	if resp.Mnemonic == "" {
		t.Fatal("expected non-empty Mnemonic in response")
	}
	words := strings.Fields(resp.Mnemonic)
	if len(words) != 24 {
		t.Fatalf("expected 24-word mnemonic, got %d words", len(words))
	}

	// resp.Key.PublicKey must exactly equal the public key derived from the mnemonic
	derivedPublicKey, _, err := cryptoadapter.DeriveX25519FromMnemonic(resp.Mnemonic)
	if err != nil {
		t.Fatalf("DeriveX25519FromMnemonic: %v", err)
	}
	if !bytes.Equal(resp.Key.PublicKey, derivedPublicKey) {
		t.Fatalf("PublicKey mismatch: key.PublicKey does not match derived public key from mnemonic")
	}

	key := resp.Key

	// Argon2idSalt must be 16 bytes
	if len(key.Argon2idSalt) != 16 {
		t.Fatalf("Argon2idSalt length: got %d, want 16", len(key.Argon2idSalt))
	}

	// WrappedPrivateKey must be >= 50 bytes
	if len(key.WrappedPrivateKey) < 50 {
		t.Fatalf("WrappedPrivateKey too short (%d bytes)", len(key.WrappedPrivateKey))
	}
}
