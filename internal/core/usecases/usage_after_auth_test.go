package usecases

import (
	"context"
	"errors"
	"testing"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// TestKeyUsageRecordedOnlyAfterAuthentication covers Q6: a file that a local
// key opens, but whose header MAC or body fails, must not change the key's
// usage counter (and thus the trial order).
func TestKeyUsageRecordedOnlyAfterAuthentication(t *testing.T) {
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	engine := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()

	pub, priv, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := kekProvider.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := kekProvider.DeriveKEK("pp", salt)
	if err != nil {
		t.Fatal(err)
	}
	fp := engine.Hash(pub)
	wrapped, err := kekProvider.WrapKey(priv, kek, fp[:16])
	if err != nil {
		t.Fatal(err)
	}
	key := &entities.IdentityKey{
		ID: fp[:16], Type: entities.KeyTypeX25519, Alias: "k", Fingerprint: fp, PublicKey: pub,
		WrappedPrivateKey: wrapped, Argon2idSalt: salt,
		StorageMode: entities.StorageModeStandard, StorageBackend: entities.StorageBackendSQLite,
	}
	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{key}}
	fh := newFakeFileHandler()
	good := buildEncryptedX25519File(t, engine, encoder, pub, []byte("usage counter"))

	_, _, macOffset, err := encoder.DecodeWithOffset(good)
	if err != nil {
		t.Fatal(err)
	}
	badMAC := append([]byte(nil), good...)
	badMAC[macOffset] ^= 1
	badBody := append([]byte(nil), good...)
	badBody[len(badBody)-1] ^= 1

	sessions := newFakeSessionStore()
	uc := NewDecryptFile(repo, engine, kekProvider, sessions, encoder, fh, &fakeProgress{}, &passphrasePrompter{passphrase: "pp"}, &fakeLogger{})
	cached := func() bool {
		kek, err := sessions.GetKEK(key.ID)
		if err != nil {
			t.Fatal(err)
		}
		return kek != nil
	}
	for name, data := range map[string][]byte{"header MAC": badMAC, "body": badBody} {
		fh.files["f.mdstn"] = data
		_, err := uc.Execute(context.Background(), &DecryptFileRequest{FilePath: "f.mdstn", OutputPath: "out", RecoveryPassphrase: "pp"})
		if !errors.Is(err, entities.ErrHeaderAuthFailed) {
			t.Fatalf("%s tamper: err = %v, want ErrHeaderAuthFailed", name, err)
		}
		if key.UsageCount != 0 || repo.updateCalls != 0 {
			t.Fatalf("%s tamper changed the key store: UsageCount=%d, Update calls=%d", name, key.UsageCount, repo.updateCalls)
		}
		if cached() {
			t.Fatalf("%s tamper: the KEK unlocked for this file was cached (R-7)", name)
		}
	}

	// R-8: an authentic file whose default output already exists changes
	// nothing in the key store either.
	fh.files["g.mdstn"] = good
	fh.files["g"] = []byte("existing")
	if _, err := uc.Execute(context.Background(), &DecryptFileRequest{FilePath: "g.mdstn", RecoveryPassphrase: "pp"}); !errors.Is(err, entities.ErrAlreadyExists) {
		t.Fatalf("existing output: err = %v, want ErrAlreadyExists", err)
	}
	if key.UsageCount != 0 || repo.updateCalls != 0 || cached() {
		t.Fatalf("existing output changed the key store: UsageCount=%d, Update calls=%d, cached=%v", key.UsageCount, repo.updateCalls, cached())
	}

	fh.files["f.mdstn"] = good
	if _, err := uc.Execute(context.Background(), &DecryptFileRequest{FilePath: "f.mdstn", OutputPath: "out2", RecoveryPassphrase: "pp"}); err != nil {
		t.Fatalf("good file: %v", err)
	}
	if key.UsageCount != 1 || repo.updateCalls != 1 {
		t.Fatalf("good file: UsageCount=%d, Update calls=%d, want 1 and 1", key.UsageCount, repo.updateCalls)
	}
	if !cached() {
		t.Fatal("good file: the KEK was not cached after the file authenticated")
	}
}
