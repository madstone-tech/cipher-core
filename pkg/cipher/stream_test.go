package cipher_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestStreamRoundTrip sends 10 MiB through EncryptStream and DecryptStream
// with bytes.Buffer for each intent. No file may appear in the working
// directory or in $HOME/.mdstn beyond the configured database.
func TestStreamRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mdstnDir := filepath.Join(home, ".mdstn")
	if err := os.MkdirAll(mdstnDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	dbPath := filepath.Join(mdstnDir, "stream.db")

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	wdBefore := dirEntries(t, wd)

	client, err := cipher.NewLocal(dbPath)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	ctx := context.Background()

	plaintext := make([]byte, 10<<20)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	const keyPass = "stream-test-key-passphrase"
	recipient, err := client.CreateKey(ctx, "stream-recipient", keyPass)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// CreateKey makes no default key, so "for me" must fail and write nothing.
	t.Run("for me without default key", func(t *testing.T) {
		var ct bytes.Buffer
		err := client.EncryptStream(ctx, bytes.NewReader(plaintext), &ct, cipher.EncryptStreamInput{KeyPassphrase: keyPass})
		if !errors.Is(err, cipher.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		if ct.Len() != 0 {
			t.Fatalf("dst holds %d bytes without a default key, want 0", ct.Len())
		}
		keys, err := client.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("EncryptStream created a key: %d keys, want 1", len(keys))
		}
	})

	// Encrypt with no intent creates the default key and returns its
	// recovery phrase. The file goes to a temp dir outside $HOME.
	seedDir := t.TempDir()
	seed := filepath.Join(seedDir, "seed.txt")
	if err := os.WriteFile(seed, []byte("seed"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	first, err := client.Encrypt(ctx, cipher.EncryptInput{
		FilePath:      seed,
		KeyPassphrase: keyPass,
		OutputPath:    filepath.Join(seedDir, "seed.txt.mdstn"),
	})
	if err != nil {
		t.Fatalf("Encrypt (create default key): %v", err)
	}
	if first.RecoveryMnemonic == "" {
		t.Fatal("Encrypt created the default key but returned no recovery phrase")
	}
	filePass := rand.Text()

	cases := []struct {
		name   string
		enc    cipher.EncryptStreamInput
		dec    cipher.DecryptStreamInput
		method cipher.EncryptionMethod
	}{
		{
			name: "recipients",
			enc: cipher.EncryptStreamInput{
				Recipients:       []cipher.Recipient{{PublicKey: recipient.Key.PublicKey}},
				OriginalFilename: "report.bin",
			},
			dec:    cipher.DecryptStreamInput{RecoveryPassphrase: keyPass},
			method: cipher.MethodX25519,
		},
		{
			name:   "password",
			enc:    cipher.EncryptStreamInput{Passphrase: filePass, OriginalFilename: "report.bin"},
			dec:    cipher.DecryptStreamInput{Passphrase: filePass},
			method: cipher.MethodPassphrase,
		},
		{
			name:   "for me",
			enc:    cipher.EncryptStreamInput{KeyPassphrase: keyPass, OriginalFilename: "report.bin"},
			dec:    cipher.DecryptStreamInput{RecoveryPassphrase: keyPass},
			method: cipher.MethodX25519,
		},
	}

	sealed := make(map[string][]byte, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ct bytes.Buffer
			if err := client.EncryptStream(ctx, bytes.NewReader(plaintext), &ct, tc.enc); err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}
			sealed[tc.name] = bytes.Clone(ct.Bytes())

			var pt bytes.Buffer
			res, err := client.DecryptStream(ctx, &ct, &pt, tc.dec)
			if err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if !bytes.Equal(pt.Bytes(), plaintext) {
				t.Fatalf("plaintext mismatch: got %d bytes, want %d", pt.Len(), len(plaintext))
			}
			if res.Method != tc.method {
				t.Errorf("Method = %q, want %q", res.Method, tc.method)
			}
			if res.OriginalFilename != "report.bin" {
				t.Errorf("OriginalFilename = %q, want %q", res.OriginalFilename, "report.bin")
			}
		})
	}

	t.Run("tampered stream", func(t *testing.T) {
		ct := bytes.Clone(sealed["recipients"])
		if len(ct) == 0 {
			t.Fatal("no sealed recipients stream")
		}
		ct[len(ct)/2] ^= 0x01
		var pt bytes.Buffer
		_, err := client.DecryptStream(ctx, bytes.NewReader(ct), &pt, cipher.DecryptStreamInput{RecoveryPassphrase: keyPass})
		if !errors.Is(err, cipher.ErrHeaderAuthFailed) {
			t.Fatalf("err = %v, want ErrHeaderAuthFailed", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		ct := sealed["password"]
		if len(ct) == 0 {
			t.Fatal("no sealed password stream")
		}
		var pt bytes.Buffer
		_, err := client.DecryptStream(ctx, bytes.NewReader(ct), &pt, cipher.DecryptStreamInput{Passphrase: rand.Text()})
		if !errors.Is(err, cipher.ErrWrongPassword) {
			t.Fatalf("err = %v, want ErrWrongPassword", err)
		}
	})

	t.Run("invalid recipient key", func(t *testing.T) {
		var ct bytes.Buffer
		err := client.EncryptStream(ctx, bytes.NewReader(plaintext), &ct, cipher.EncryptStreamInput{
			Recipients: []cipher.Recipient{{PublicKey: make([]byte, 31)}},
		})
		if !errors.Is(err, cipher.ErrInvalidRecipientKey) {
			t.Fatalf("err = %v, want ErrInvalidRecipientKey", err)
		}
		if ct.Len() != 0 {
			t.Fatalf("dst holds %d bytes after an invalid recipient key, want 0", ct.Len())
		}
	})

	if got := dirEntries(t, wd); !slices.Equal(got, wdBefore) {
		t.Errorf("working directory changed: before %v, after %v", wdBefore, got)
	}
	for _, name := range dirEntries(t, mdstnDir) {
		switch name {
		case "stream.db", "stream.db-wal", "stream.db-shm", "stream.db-journal":
		default:
			t.Errorf("unexpected file in $HOME/.mdstn: %s", name)
		}
	}
	for _, name := range dirEntries(t, home) {
		if name != ".mdstn" {
			t.Errorf("unexpected entry in $HOME: %s", name)
		}
	}
}
