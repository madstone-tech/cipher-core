package cipher_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// sealForKey creates a key with passphrase and returns the client and a
// stream sealed to that key.
func sealForKey(t *testing.T, passphrase string) (*cipher.Client, []byte) {
	t.Helper()
	ctx := context.Background()
	c := newInMemoryClient(t)
	res, err := c.CreateKey(ctx, "n1", passphrase)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	var sealed bytes.Buffer
	if err := c.EncryptStream(ctx, bytes.NewReader([]byte("n1 payload")), &sealed, cipher.EncryptStreamInput{
		Recipients: []cipher.Recipient{{PublicKey: res.Key.PublicKey}},
	}); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	return c, sealed.Bytes()
}

func decryptWith(c *cipher.Client, sealed []byte, passphrase string) error {
	var out bytes.Buffer
	_, err := c.DecryptStream(context.Background(), bytes.NewReader(sealed), &out, cipher.DecryptStreamInput{RecoveryPassphrase: passphrase})
	return err
}

// TestSuppliedPassphraseIsAlwaysChecked covers N1: after a successful unlock,
// a WRONG passphrase must still fail; only an EMPTY passphrase uses the cache.
func TestSuppliedPassphraseIsAlwaysChecked(t *testing.T) {
	c, sealed := sealForKey(t, "right-passphrase")

	if err := decryptWith(c, sealed, "right-passphrase"); err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
	if err := decryptWith(c, sealed, "wrong-passphrase"); err == nil {
		t.Fatal("a wrong passphrase decrypted after an unlock (N1)")
	}
	if err := decryptWith(c, sealed, ""); err != nil {
		t.Fatalf("empty passphrase must use the cached unlock: %v", err)
	}

	if err := c.LockAll(); err != nil {
		t.Fatalf("LockAll: %v", err)
	}
	if err := decryptWith(c, sealed, ""); err == nil {
		t.Fatal("after LockAll, an empty passphrase still decrypted")
	}
}

// TestConcurrentCallsKeepPassphrasesApart runs a right and a wrong passphrase
// at the same time on one client. Under -race it also proves that no
// passphrase state is shared between calls (N8).
func TestConcurrentCallsKeepPassphrasesApart(t *testing.T) {
	c, sealed := sealForKey(t, "right-passphrase")
	if err := c.LockAll(); err != nil {
		t.Fatalf("LockAll: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pp := "right-passphrase"
			if i%2 == 1 {
				pp = "wrong-passphrase"
			}
			errs[i] = decryptWith(c, sealed, pp)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if i%2 == 0 && err != nil {
			t.Errorf("call %d (right passphrase): %v", i, err)
		}
		if i%2 == 1 && err == nil {
			t.Errorf("call %d (wrong passphrase) succeeded", i)
		}
	}
}
