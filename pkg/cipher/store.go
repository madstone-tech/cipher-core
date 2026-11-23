package cipher

import (
	"context"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// StoreWrappedKeyInput carries a key whose private half was wrapped by the
// caller. This is the zero-knowledge path: the wrapping happens outside this
// library — in a browser, typically — and nothing here can unwrap it.
type StoreWrappedKeyInput struct {
	// Alias is the human-facing name for the key.
	Alias string
	// PublicKey is the raw 32-byte X25519 public key.
	PublicKey []byte
	// WrappedPrivateKey is caller-produced ciphertext, opaque to this library.
	WrappedPrivateKey []byte
	// Argon2idSalt is the salt the caller used to derive its wrapping KEK.
	Argon2idSalt []byte
}

// StoreWrappedKey records a client-wrapped identity key. The private key is
// never seen in plaintext by this library or by anything it writes to.
func (c *Client) StoreWrappedKey(ctx context.Context, in StoreWrappedKeyInput) (*KeyInfo, error) {
	key, err := c.storeWrap.Execute(ctx, &usecases.StoreWrappedKeyRequest{
		Alias:             in.Alias,
		Type:              KeyTypeX25519,
		PublicKey:         in.PublicKey,
		WrappedPrivateKey: in.WrappedPrivateKey,
		Argon2idSalt:      in.Argon2idSalt,
	})
	if err != nil {
		return nil, err
	}
	return toKeyInfo(key), nil
}
