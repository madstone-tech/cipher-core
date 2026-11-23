package cipher

import (
	"context"
	"fmt"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// KeyInfo is the read model for a stored identity key.
type KeyInfo struct {
	ID          string
	Alias       string
	Type        KeyType
	Fingerprint string
	PublicKey   []byte
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	IsDefault   bool
}

// KeyResult is the outcome of key creation: the stored key plus the BIP39
// recovery mnemonic (shown exactly once — the SDK returns it, the caller is
// responsible for surfacing it to the user).
type KeyResult struct {
	Key      *KeyInfo
	Mnemonic string
}

// CreateKey generates a new X25519 identity key (the only generated type).
// The passphrase wraps the private key at rest (Argon2id).
//
// CreateKey also starts a session for the new key: for Config.SessionTTL
// (default DefaultSessionTTL), a call on this Client with an EMPTY key
// passphrase can use the key without the passphrase. A given passphrase is
// always checked. Call Lock(keyID) or LockAll to end the session at once, for
// example in a service that serves more than one caller with one Client.
func (c *Client) CreateKey(ctx context.Context, alias, passphrase string) (*KeyResult, error) {
	resp, err := c.createUC.Execute(ctx, &usecases.CreateKeyRequest{
		Alias:      alias,
		Passphrase: passphrase,
	})
	if err != nil {
		return nil, fmt.Errorf("cipher: create key: %w", err)
	}
	return &KeyResult{
		Key:      toKeyInfo(resp.Key),
		Mnemonic: resp.Mnemonic,
	}, nil
}

// ListKeys returns all stored identity keys.
func (c *Client) ListKeys(ctx context.Context) ([]*KeyInfo, error) {
	resp, err := c.manageUC.ListKeys(ctx, &usecases.ListKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("cipher: list keys: %w", err)
	}
	out := make([]*KeyInfo, len(resp.Keys))
	for i, k := range resp.Keys {
		out[i] = toKeyInfo(k)
	}
	return out, nil
}

// GetKey returns a single key by ID.
func (c *Client) GetKey(ctx context.Context, id string) (*KeyInfo, error) {
	resp, err := c.manageUC.GetKey(ctx, &usecases.GetKeyRequest{ID: id})
	if err != nil {
		return nil, fmt.Errorf("cipher: get key: %w", err)
	}
	return toKeyInfo(resp.Key), nil
}

// DeleteKey removes a key by ID. Irreversible.
func (c *Client) DeleteKey(ctx context.Context, id string) error {
	if err := c.manageUC.DeleteKey(ctx, &usecases.DeleteKeyRequest{ID: id}); err != nil {
		return fmt.Errorf("cipher: delete key: %w", err)
	}
	return nil
}

// AliasKey renames a key's alias.
func (c *Client) AliasKey(ctx context.Context, id, alias string) error {
	if err := c.manageUC.AliasKey(ctx, &usecases.AliasKeyRequest{ID: id, Alias: alias}); err != nil {
		return fmt.Errorf("cipher: alias key: %w", err)
	}
	return nil
}

// ExportKey exports a key's public material in the given format ("pem" or "raw").
func (c *Client) ExportKey(ctx context.Context, id, format string) ([]byte, error) {
	resp, err := c.manageUC.ExportKey(ctx, &usecases.ExportKeyRequest{ID: id, Format: format})
	if err != nil {
		return nil, fmt.Errorf("cipher: export key: %w", err)
	}
	return resp.Data, nil
}

// toKeyInfo converts the entity to the SDK read model.
func toKeyInfo(k *entities.IdentityKey) *KeyInfo {
	if k == nil {
		return nil
	}
	return &KeyInfo{
		ID:          k.ID,
		Alias:       k.Alias,
		Type:        k.Type,
		Fingerprint: k.Fingerprint,
		PublicKey:   k.PublicKey,
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
		IsDefault:   k.IsDefault,
	}
}
