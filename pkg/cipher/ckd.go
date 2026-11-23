package cipher

import (
	"context"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// CKDKey is the resolved public key for an email address.
type CKDKey struct {
	Email       string
	PublicKey   []byte
	Fingerprint string
	FromCache   bool // true when served from the local TOFU cache
}

// LookupKey resolves a recipient's public key by email via CKD. The first
// lookup for an email pins the key in the local TOFU cache; subsequent
// lookups serve from cache and surface changes rather than silently
// accepting them.
func (c *Client) LookupKey(ctx context.Context, email string) (*CKDKey, error) {
	resp, err := c.lookupUC.Execute(ctx, &usecases.LookupKeyRequest{Email: email})
	if err != nil {
		return nil, fmt.Errorf("cipher: ckd lookup: %w", err)
	}
	return &CKDKey{
		Email:       email,
		PublicKey:   resp.PublicKey,
		Fingerprint: resp.Fingerprint,
		FromCache:   resp.FromCache,
	}, nil
}

// PublishKey publishes the caller's public key to the CKD directory for the
// given email, making the caller discoverable by email. CKD publish is free
// by design — it is the network-effect side of discovery.
func (c *Client) PublishKey(ctx context.Context, email, keyID string) (string, error) {
	resp, err := c.publishUC.Execute(ctx, &usecases.PublishKeyRequest{
		Email: email,
		KeyID: keyID,
	})
	if err != nil {
		return "", fmt.Errorf("cipher: ckd publish: %w", err)
	}
	return resp.EmailHash, nil
}
