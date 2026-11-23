package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncryptRecipientKeyNoTTY encrypts to a raw public key with stdin from
// /dev/null in an empty key store: no prompt, exit 0, and the encrypting
// store holds no key. The owner of the key decrypts with
// --key-passphrase-file (quickstart.md §3).
func TestEncryptRecipientKeyNoTTY(t *testing.T) {
	dir := t.TempDir()
	ownerDB := filepath.Join(dir, "owner", "cipher.db")
	senderDir := filepath.Join(dir, "sender")
	for _, d := range []string{filepath.Dir(ownerDB), senderDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	senderDB := filepath.Join(senderDir, "cipher.db")

	pub := createKey(t, dir, ownerDB, "owner-pass")

	plain := make([]byte, 3<<20) // stream framing
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	src := writeTestFile(t, dir, "snap.db", plain)
	enc := filepath.Join(dir, "snap.mdstn")

	r := mustCLI(t, dir, "--db", senderDB, "encrypt", src,
		"--recipient-key", base64.StdEncoding.EncodeToString(pub), "-o", enc)
	for _, s := range []string{r.stdout, r.stderr} {
		if strings.Contains(s, "Enter ") || strings.Contains(strings.ToLower(s), "password:") {
			t.Fatalf("encrypt printed a prompt:\nstdout: %s\nstderr: %s", r.stdout, r.stderr)
		}
	}
	if keys := listKeys(t, dir, senderDB); len(keys) != 0 {
		t.Fatalf("encrypting store holds %d keys; want 0", len(keys))
	}

	passFile := writeTestFile(t, dir, "decrypt.pass", []byte("owner-pass\r\n"))
	out := filepath.Join(dir, "out.db")
	mustCLI(t, dir, "--db", ownerDB, "decrypt", enc, "--key-passphrase-file", passFile, "-o", out)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted bytes differ from the source")
	}
}

// TestEncryptFlagRules checks the flag rules of contracts/cli.md §encrypt:
// each case exits 1 and writes no output.
func TestEncryptFlagRules(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "cipher.db")
	src := writeTestFile(t, dir, "in.txt", []byte("hello"))
	pwFile := writeTestFile(t, dir, "pw", []byte("pw\n"))
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	// A random 32-byte string is a valid X25519 public key with
	// overwhelming probability.
	keyB64 := base64.StdEncoding.EncodeToString(key)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"password and password-file", []string{"--password", "x", "--password-file", pwFile}, "mutually exclusive"},
		{"recipient-key and password", []string{"--recipient-key", keyB64, "--password", "x"}, "mutually exclusive"},
		{"recipient-key and password-file", []string{"--recipient-key", keyB64, "--password-file", pwFile}, "mutually exclusive"},
		{"for and password", []string{"--for", "a@example.com", "--password", "x"}, "mutually exclusive"},
		{"invalid recipient-key", []string{"--recipient-key", "AAAA"}, "invalid recipient public key"},
		{"low-order recipient-key", []string{"--recipient-key", base64.StdEncoding.EncodeToString(make([]byte, 32))}, "invalid recipient public key"},
		{"no terminal and no secret", nil, "--password-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".mdstn")
			args := append([]string{"--db", db, "encrypt", src, "-o", out}, tc.args...)
			r := runCLI(t, dir, args...)
			if r.code != 1 {
				t.Fatalf("exit %d; want 1\nstderr: %s", r.code, r.stderr)
			}
			if !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("stderr %q does not contain %q", r.stderr, tc.want)
			}
			if strings.Contains(r.stderr, "Usage:") {
				t.Fatalf("runtime error printed the usage:\n%s", r.stderr)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("output %s exists after a usage error (stat: %v)", out, err)
			}
		})
	}
}

// TestKeysCreatePassphrasePriority checks --key-passphrase >
// --key-passphrase-file: a file decrypts with the flag value.
func TestKeysCreatePassphrasePriority(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "cipher.db")
	fileOnly := writeTestFile(t, dir, "file.pass", []byte("from-file\n"))
	mustCLI(t, dir, "--db", db, "keys", "create", "--key-passphrase", "from-flag",
		"--key-passphrase-file", fileOnly, "--yes", "--json")
	keys := listKeys(t, dir, db)
	if len(keys) != 1 {
		t.Fatalf("%d keys; want 1", len(keys))
	}

	src := writeTestFile(t, dir, "in.txt", []byte("priority"))
	enc := filepath.Join(dir, "in.mdstn")
	mustCLI(t, dir, "--db", db, "encrypt", src, "--recipient-key",
		base64.StdEncoding.EncodeToString(keys[0].PublicKey), "-o", enc)

	flagPass := writeTestFile(t, dir, "flag.pass", []byte("from-flag\n"))
	if r := runCLI(t, dir, "--db", db, "decrypt", enc, "--key-passphrase-file", fileOnly, "-o", filepath.Join(dir, "x1")); r.code == 0 {
		t.Fatal("decrypt with the --key-passphrase-file value succeeded; --key-passphrase must win")
	}
	mustCLI(t, dir, "--db", db, "decrypt", enc, "--key-passphrase-file", flagPass, "-o", filepath.Join(dir, "x2"))
}
