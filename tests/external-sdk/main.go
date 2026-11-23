// Command externalsdk proves pkg/cipher is consumable from outside the module.
//
// It imports ONLY github.com/madstone-tech/cipher-core/pkg/cipher plus stdlib. If
// any step here needed an internal/ path, Go's internal-visibility rule would
// refuse to compile it from this separate module.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

const payload = "external module round-trip payload"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "external-sdk: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("external-sdk: round trip OK")
}

func run() (err error) {
	dir, err := os.MkdirTemp("", "external-sdk-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()

	// The SDK refuses outputs in the folder of its key database: keep the
	// database in its own folder.
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		return err
	}
	client, err := cipher.NewLocal(filepath.Join(keys, "cipher.db"))
	if err != nil {
		return fmt.Errorf("NewLocal: %w", err)
	}
	defer func() { err = errors.Join(err, client.Close()) }()

	ctx := context.Background()

	// The secrets are random per run, so no literal secret lives in the tree.
	filePassword := rand.Text()
	keyPassphrase := rand.Text()

	key, err := client.CreateKey(ctx, "external", keyPassphrase)
	if err != nil {
		return fmt.Errorf("CreateKey: %w", err)
	}

	if err := fileRoundTrip(ctx, client, dir, filePassword); err != nil {
		return err
	}
	if err := streamRoundTrip(ctx, client, cipher.EncryptStreamInput{Passphrase: filePassword},
		cipher.DecryptStreamInput{Passphrase: filePassword}); err != nil {
		return fmt.Errorf("stream (password): %w", err)
	}
	if err := streamRoundTrip(ctx, client,
		cipher.EncryptStreamInput{Recipients: []cipher.Recipient{{PublicKey: key.Key.PublicKey}}},
		cipher.DecryptStreamInput{RecoveryPassphrase: keyPassphrase}); err != nil {
		return fmt.Errorf("stream (recipient): %w", err)
	}
	return nil
}

// fileRoundTrip encrypts and decrypts through the file methods. It hands the
// container and its password to the shell runner for the CLI cross-check.
func fileRoundTrip(ctx context.Context, client *cipher.Client, dir, filePassword string) error {
	src := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(src, []byte(payload), 0o600); err != nil {
		return err
	}

	enc, err := client.Encrypt(ctx, cipher.EncryptInput{
		FilePath:   src,
		Passphrase: filePassword,
	})
	if err != nil {
		return fmt.Errorf("Encrypt: %w", err)
	}

	if out := os.Getenv("EXTERNAL_SDK_OUT"); out != "" {
		b, err := os.ReadFile(enc.OutputPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, b, 0o600); err != nil { // #nosec G703 -- test harness: run.sh sets the path
			return err
		}
	}
	if out := os.Getenv("EXTERNAL_SDK_PASSWORD_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(filePassword), 0o600); err != nil { // #nosec G703 -- test harness: run.sh sets the path
			return err
		}
	}

	dec, err := client.Decrypt(ctx, cipher.DecryptInput{
		FilePath:   enc.OutputPath,
		Passphrase: filePassword,
		OutputPath: filepath.Join(dir, "roundtrip.txt"),
	})
	if err != nil {
		return fmt.Errorf("Decrypt: %w", err)
	}

	got, err := os.ReadFile(dec.OutputPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, []byte(payload)) {
		return fmt.Errorf("file round-trip mismatch: got %q, want %q", got, payload)
	}
	return nil
}

// streamRoundTrip encrypts and decrypts through EncryptStream and
// DecryptStream with in-memory buffers only.
func streamRoundTrip(ctx context.Context, client *cipher.Client, enc cipher.EncryptStreamInput, dec cipher.DecryptStreamInput) error {
	var ct bytes.Buffer
	if err := client.EncryptStream(ctx, bytes.NewReader([]byte(payload)), &ct, enc); err != nil {
		return fmt.Errorf("EncryptStream: %w", err)
	}
	var pt bytes.Buffer
	if _, err := client.DecryptStream(ctx, &ct, &pt, dec); err != nil {
		return fmt.Errorf("DecryptStream: %w", err)
	}
	if !bytes.Equal(pt.Bytes(), []byte(payload)) {
		return fmt.Errorf("stream round-trip mismatch: got %q, want %q", pt.Bytes(), payload)
	}
	return nil
}
