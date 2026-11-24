package usecases

import (
	"context"
	"fmt"
	"time"
)

// LookupKeyRequest contains the email to look up.
type LookupKeyRequest struct {
	Email string
}

// LookupKeyResponse contains the public key resolved from CKD.
type LookupKeyResponse struct {
	PublicKey   []byte
	Fingerprint string
	KeyType     string
	FromCache   bool
}

// LookupKey resolves a recipient's public key via the CKD network, using a
// local TOFU cache. The cache-check → network-fetch → cache-write chain is
// owned entirely by this usecase.
type LookupKey struct {
	client CKDClient
	cache  CKDCacheRepository
	logger Logger
}

// NewLookupKey creates a new LookupKey usecase.
func NewLookupKey(client CKDClient, cache CKDCacheRepository, logger Logger) *LookupKey {
	return &LookupKey{
		client: client,
		cache:  cache,
		logger: logger,
	}
}

// Execute resolves the public key for the given email address.
// On a cache hit it updates LastSeen and returns FromCache: true.
// On a cache miss it fetches from the CKD network, writes to cache, and
// returns FromCache: false.
func (uc *LookupKey) Execute(ctx context.Context, req *LookupKeyRequest) (*LookupKeyResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("lookup key: email must not be empty")
	}

	// Cache hit?
	cached, err := uc.cache.Get(ctx, req.Email, "")
	if err == nil && cached != nil {
		// Update last-seen timestamp
		cached.LastSeen = time.Now().Unix()
		if setErr := uc.cache.Set(ctx, cached); setErr != nil {
			uc.logger.Warn("lookup key: failed to update cache last-seen", map[string]interface{}{
				"email": req.Email,
				"error": setErr.Error(),
			})
		}
		uc.logger.Debug("lookup key: cache hit", map[string]interface{}{"email": req.Email})
		keyType := cached.KeyType
		if keyType == "" {
			keyType = DefaultCKDKeyType
		}
		return &LookupKeyResponse{
			PublicKey:   cached.PublicKey,
			Fingerprint: cached.Fingerprint,
			KeyType:     keyType,
			FromCache:   true,
		}, nil
	}

	// Cache miss — fetch from network
	uc.logger.Debug("lookup key: cache miss, fetching from network", map[string]interface{}{"email": req.Email})
	ckdKey, err := uc.client.LookupKey(ctx, req.Email)
	if err != nil {
		uc.logger.Error("lookup key: CKD network fetch failed", map[string]interface{}{
			"email": req.Email,
			"error": err.Error(),
		})
		return nil, fmt.Errorf("lookup key for %q: %w", req.Email, err)
	}

	// Write to cache
	fetchedType := ckdKey.KeyType
	if fetchedType == "" {
		fetchedType = DefaultCKDKeyType
	}
	entry := &CKDCacheEntry{
		Email:       req.Email,
		KeyType:     fetchedType,
		PublicKey:   ckdKey.PublicKey,
		Fingerprint: ckdKey.Fingerprint,
		FirstSeen:   time.Now().Unix(),
		LastSeen:    time.Now().Unix(),
	}
	if setErr := uc.cache.Set(ctx, entry); setErr != nil {
		uc.logger.Warn("lookup key: failed to write to cache", map[string]interface{}{
			"email": req.Email,
			"error": setErr.Error(),
		})
		// Non-fatal: still return the resolved key
	}

	return &LookupKeyResponse{
		PublicKey:   ckdKey.PublicKey,
		Fingerprint: ckdKey.Fingerprint,
		KeyType:     fetchedType,
		FromCache:   false,
	}, nil
}
