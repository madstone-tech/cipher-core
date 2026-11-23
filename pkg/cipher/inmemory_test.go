package cipher_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

func newInMemoryClient(t *testing.T) *cipher.Client {
	t.Helper()
	c, err := cipher.New(cipher.Config{DBPath: cipher.InMemory})
	if err != nil {
		t.Fatalf("New(InMemory): %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// dirEntries returns the names in dir ("" entries when dir does not exist).
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// TestInMemoryEncryptToPublicKey encrypts to a raw public key with a client
// that has no key database on disk, and decrypts with a second in-memory
// client that holds the key. Neither client creates a file in the working
// directory or in $HOME/.mdstn.
func TestInMemoryEncryptToPublicKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	work := t.TempDir()
	t.Chdir(work)
	data := t.TempDir()

	ctx := context.Background()
	owner := newInMemoryClient(t)
	key, err := owner.CreateKey(ctx, "owner", "owner-pass")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	sender := newInMemoryClient(t)
	plain := make([]byte, 3<<20)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(data, "snap.db")
	if err := os.WriteFile(src, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(data, "snap.mdstn")
	if _, err := sender.Encrypt(ctx, cipher.EncryptInput{
		FilePath:   src,
		Recipients: []cipher.Recipient{{PublicKey: key.Key.PublicKey, Fingerprint: cipher.Fingerprint(key.Key.PublicKey)}},
		OutputPath: enc,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	senderKeys, err := sender.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(senderKeys) != 0 {
		t.Fatalf("sender holds %d keys; want 0", len(senderKeys))
	}

	out := filepath.Join(data, "out.db")
	if _, err := owner.Decrypt(ctx, cipher.DecryptInput{
		FilePath:           enc,
		RecoveryPassphrase: "owner-pass",
		OutputPath:         out,
	}); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted bytes differ from the source")
	}

	if names := dirEntries(t, work); len(names) != 0 {
		t.Errorf("working directory holds %v; want no files", names)
	}
	if names := dirEntries(t, filepath.Join(home, ".mdstn")); names != nil {
		t.Errorf("$HOME/.mdstn exists with %v; want no directory", names)
	}
	if names := dirEntries(t, home); len(names) != 0 {
		t.Errorf("$HOME holds %v; want no files", names)
	}
	want := map[string]bool{"snap.db": true, "snap.mdstn": true, "out.db": true}
	for _, n := range dirEntries(t, data) {
		if !want[n] {
			t.Errorf("unexpected file %s in the data directory", n)
		}
	}
}

// TestEncryptRejectsInvalidPublicKey checks that Encrypt rejects a bad
// Recipient.PublicKey with ErrInvalidRecipientKey before it writes output.
func TestEncryptRejectsInvalidPublicKey(t *testing.T) {
	c := newInMemoryClient(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"short":      make([]byte, 31),
		"zero point": make([]byte, 32),
		"point one":  append([]byte{1}, make([]byte, 31)...),
	}
	for name, pub := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, name+".mdstn")
			_, err := c.Encrypt(context.Background(), cipher.EncryptInput{
				FilePath:   src,
				Recipients: []cipher.Recipient{{PublicKey: pub}},
				OutputPath: out,
			})
			if !errors.Is(err, entities.ErrInvalidRecipientKey) {
				t.Fatalf("Encrypt error = %v; want ErrInvalidRecipientKey", err)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output exists after a rejected key (stat: %v)", err)
			}
		})
	}
}
