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
	KeyType     string // declared by the response; "x25519" today
	FromCache   bool   // true when served from the local TOFU cache
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
		KeyType:     resp.KeyType,
		FromCache:   resp.FromCache,
	}, nil
}

// PublishKey publishes the caller's public key to the CKD directory for the
// given email, making the caller discoverable by email. CKD publish is free
// by design — it is the network-effect side of discovery. The directory
// token resolves from Config.PublishToken and the KD_TOKEN environment
// variable; a rotation (key changed, or tombstone re-bind inside the 30-day
// window) needs the server's current fingerprint via PublishFingerprint.
// A pinned binding answered with nothing but the token yields a
// 409-conflict-class error whose text carries the required fingerprint.
func (c *Client) PublishKey(ctx context.Context, email, keyID string) (*PublishInfo, error) {
	if c.publisher == nil {
		return nil, fmt.Errorf("cipher: ckd publish unavailable: no directory token configured (set Config.PublishToken or the KD_TOKEN environment variable; get one at https://keys.mdstn.dev by verifying your email)")
	}
	resp, err := c.publishUC.Execute(ctx, &usecases.PublishKeyRequest{
		Email:       email,
		KeyID:       keyID,
		Fingerprint: c.publishFingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("cipher: ckd publish: %w", err)
	}
	return &PublishInfo{
		EmailHash: resp.EmailHash,
		Rotated:   resp.Rotated,
		Rebound:   resp.Rebound,
	}, nil
}

// PublishInfo reports the directory's publish result.
type PublishInfo struct {
	EmailHash string
	Rotated   bool // this call replaced an existing binding
	Rebound   bool // this call cleared a tombstone inside the window
}

// UnpublishKey removes the email's binding from the directory (idempotent
// server-side; the binding becomes a 30-day tombstone).
func (c *Client) UnpublishKey(ctx context.Context, email string) error {
	if c.publisher == nil {
		return fmt.Errorf("cipher: ckd unpublish unavailable: no directory token configured (set Config.PublishToken or the KD_TOKEN environment variable)")
	}
	if err := c.publisher.Unpublish(ctx, email); err != nil {
		return fmt.Errorf("cipher: ckd unpublish: %w", err)
	}
	return nil
}

// KeyStatus reports whether a fingerprint is published on the directory.
// Tombstoned bindings report Published: false.
func (c *Client) KeyStatus(ctx context.Context, fingerprint string) (*KeyStatusInfo, error) {
	if c.publisher == nil {
		return nil, fmt.Errorf("cipher: ckd status unavailable: no directory token configured (set Config.PublishToken or the KD_TOKEN environment variable)")
	}
	resp, err := c.publisher.Status(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("cipher: ckd status: %w", err)
	}
	return &KeyStatusInfo{
		Published:   resp.Published,
		Fingerprint: resp.Fingerprint,
		EmailHash:   resp.EmailHash,
	}, nil
}

// KeyStatusInfo mirrors the directory's status response.
type KeyStatusInfo struct {
	Published   bool
	Fingerprint string
	EmailHash   string
}
