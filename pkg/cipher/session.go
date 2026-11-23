package cipher

import (
	"context"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
)

// DefaultSessionTTL is how long Unlock caches a derived KEK when Config leaves
// SessionTTL unset. It matches the CLI's ssh-agent-style session window.
const DefaultSessionTTL = crypto.DefaultSessionTTL

// Unlock derives the key-encryption key for keyID from passphrase and caches
// it for the client's session TTL, so later operations on that key need no
// passphrase.
//
// Argon2id derivation alone cannot tell a right passphrase from a wrong one —
// both produce 32 bytes. So the derived KEK is verified by unwrapping the
// stored private key before it is cached. Caching an unverified KEK would turn
// a typo into a confusing failure several calls later, far from its cause.
func (c *Client) Unlock(ctx context.Context, keyID, passphrase string) error {
	if keyID == "" {
		return fmt.Errorf("key id must not be empty")
	}
	if passphrase == "" {
		return fmt.Errorf("passphrase must not be empty")
	}

	key, err := c.keyRepo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to load key %s: %w", keyID, err)
	}

	kek, err := c.kekProvider.DeriveKEK(passphrase, key.Argon2idSalt)
	if err != nil {
		return fmt.Errorf("failed to derive KEK: %w", err)
	}
	defer c.kekProvider.ZeroKEK(kek)

	if _, err := c.kekProvider.UnwrapKey(key.WrappedPrivateKey, kek, keyID); err != nil {
		return fmt.Errorf("incorrect passphrase for key %s", keyID)
	}

	if err := c.sessionStore.SetKEK(keyID, kek, c.sessionTTL); err != nil {
		return fmt.Errorf("failed to cache session key: %w", err)
	}
	return nil
}

// Lock zeroes and drops the cached KEK for a single key.
func (c *Client) Lock(keyID string) error {
	return c.sessionStore.ClearKey(keyID)
}

// LockAll zeroes and drops every cached KEK held by this client.
func (c *Client) LockAll() error {
	return c.sessionStore.Clear()
}
