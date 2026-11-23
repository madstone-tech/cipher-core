package cipher_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// newTestClient constructs an SDK client over a temp SQLite DB.
func newTestClient(t *testing.T) *cipher.Client {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	client, err := cipher.NewLocal(dbPath)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return client
}

// writeFile creates a temp file with the given content and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// tempDest returns a path inside a fresh temp dir for use as an explicit
// output destination. Decrypt defaults to the original filename resolved
// against the working directory, which during `go test` is the package
// directory — passing an explicit destination keeps test output out of the
// source tree.
func tempDest(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// TestSDKRoundTrip_Passphrase exercises the full SDK path: encrypt
// (passphrase) → decrypt, verifying the .mdstn container round-trips.
func TestSDKRoundTrip_Passphrase(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	secret := "round-trip secret payload — sdk test"
	src := writeFile(t, "secret.txt", secret)

	res, err := client.Encrypt(ctx, cipher.EncryptInput{
		FilePath:   src,
		Passphrase: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res.OutputPath == "" {
		t.Fatal("Encrypt returned empty OutputPath")
	}
	if res.Method != cipher.MethodPassphrase {
		t.Fatalf("Encrypt method = %q, want %q", res.Method, cipher.MethodPassphrase)
	}

	dec, err := client.Decrypt(ctx, cipher.DecryptInput{
		FilePath:   res.OutputPath,
		Passphrase: "correct horse battery staple",
		OutputPath: tempDest(t, "secret.txt"),
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	got, err := os.ReadFile(dec.OutputPath)
	if err != nil {
		t.Fatalf("ReadFile decrypted: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, secret)
	}
}

// TestSDKRoundTrip_ForMe exercises key-based encrypt-for-me: create a key
// (receiving the mnemonic), then encrypt and decrypt with it.
func TestSDKRoundTrip_ForMe(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	key, err := client.CreateKey(ctx, "sdk-test", "key-passphrase-123")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if key.Key == nil || key.Key.Fingerprint == "" {
		t.Fatal("CreateKey returned no key info")
	}
	if key.Mnemonic == "" {
		t.Fatal("CreateKey returned empty mnemonic — SDK mode must surface it")
	}

	secret := "for-me payload"
	src := writeFile(t, "doc.txt", secret)
	res, err := client.Encrypt(ctx, cipher.EncryptInput{
		FilePath:      src,
		KeyPassphrase: "key-passphrase-123",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res.Method != cipher.MethodX25519 {
		t.Fatalf("Encrypt method = %q, want %q", res.Method, cipher.MethodX25519)
	}

	dec, err := client.Decrypt(ctx, cipher.DecryptInput{
		FilePath:           res.OutputPath,
		RecoveryPassphrase: "key-passphrase-123",
		OutputPath:         tempDest(t, "doc.txt"),
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	got, err := os.ReadFile(dec.OutputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, secret)
	}
}

// TestSDKRecoverFromMnemonic verifies headless recovery: derive from the
// mnemonic returned by CreateKey and confirm the same key comes back via
// the re-wrap path (new passphrase), plus pure-derivation agreement.
func TestSDKRecoverFromMnemonic(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	created, err := client.CreateKey(ctx, "original", "original-pass")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Recover into the same store with a NEW passphrase (re-wrap path).
	rec, err := client.RecoverFromMnemonic(ctx, created.Mnemonic, "new-pass")
	if err != nil {
		t.Fatalf("RecoverFromMnemonic: %v", err)
	}
	if rec.Fingerprint != created.Key.Fingerprint {
		t.Fatalf("recovered fingerprint %q != created %q", rec.Fingerprint, created.Key.Fingerprint)
	}

	// Pure derivation must match the stored public key.
	pub, _, err := cipher.DeriveFromMnemonic(created.Mnemonic)
	if err != nil {
		t.Fatalf("DeriveFromMnemonic: %v", err)
	}
	if string(pub) != string(created.Key.PublicKey) {
		t.Fatal("pure derivation public key != created key public key")
	}
}
