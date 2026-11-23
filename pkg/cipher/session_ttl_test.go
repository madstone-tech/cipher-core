package cipher_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestCreateKeySessionUsesConfiguredTTL covers R-11: the session that
// CreateKey starts lasts Config.SessionTTL, not a hard-coded 30 minutes.
func TestCreateKeySessionUsesConfiguredTTL(t *testing.T) {
	ctx := context.Background()
	c, err := cipher.New(cipher.Config{DBPath: cipher.InMemory, SessionTTL: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	res, err := c.CreateKey(ctx, "ttl", "ttl-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := c.EncryptStream(ctx, bytes.NewReader([]byte("ttl")), &sealed, cipher.EncryptStreamInput{
		Recipients: []cipher.Recipient{{PublicKey: res.Key.PublicKey}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := decryptWith(c, sealed.Bytes(), ""); err != nil {
		t.Fatalf("inside the TTL, an empty passphrase must use the session: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := decryptWith(c, sealed.Bytes(), ""); err == nil {
		t.Fatal("after the configured TTL, the session still decrypted")
	}
}
