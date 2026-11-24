package usecases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// PublishKeyRequest contains parameters for publishing a key to CKD.
// PublicKey is used directly when the caller already has the raw bytes;
// KeyID can alternatively be supplied to let the usecase fetch the key
// from the repository.
type PublishKeyRequest struct {
	Email       string
	PublicKey   []byte // Raw public key bytes (preferred)
	KeyID       string // Alternative: look up key by ID (used if PublicKey is nil)
	Fingerprint string // Rotation factor: the server's current (or tombstone) fingerprint; blank = fresh publish
}

// PublishKeyResponse contains the result of publishing a key.
type PublishKeyResponse struct {
	EmailHash string
	Rotated   bool // the call replaced an existing binding
	Rebound   bool // the call cleared a tombstone inside the window
}

// PublishKey publishes a user's public key to the CKD network.
// It owns email hashing and delegates to the CKDPublisher port.
type PublishKey struct {
	publisher CKDPublisher
	keyRepo   KeyRepository
	logger    Logger
}

// NewPublishKey creates a new PublishKey usecase.
func NewPublishKey(publisher CKDPublisher, keyRepo KeyRepository, logger Logger) *PublishKey {
	return &PublishKey{
		publisher: publisher,
		keyRepo:   keyRepo,
		logger:    logger,
	}
}

// Execute publishes the key to CKD.
// If req.PublicKey is provided it is used directly.
// Otherwise the key is fetched from the repository using req.KeyID.
func (uc *PublishKey) Execute(ctx context.Context, req *PublishKeyRequest) (*PublishKeyResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("publish key: email must not be empty")
	}

	publicKey := req.PublicKey
	if len(publicKey) == 0 {
		if req.KeyID == "" {
			return nil, fmt.Errorf("publish key: either PublicKey or KeyID must be provided")
		}
		key, err := uc.keyRepo.GetByID(ctx, req.KeyID)
		if err != nil {
			return nil, fmt.Errorf("publish key: get key %q: %w", req.KeyID, err)
		}
		if len(key.PublicKey) == 0 {
			return nil, fmt.Errorf("publish key: key %q has no public key component", req.KeyID)
		}
		publicKey = key.PublicKey
	}

	resp, err := uc.publisher.Publish(ctx, req.Email, publicKey, req.Fingerprint)
	if err != nil {
		uc.logger.Error("publish key: CKD publish failed", map[string]interface{}{
			"email": req.Email,
			"error": err.Error(),
		})
		return nil, fmt.Errorf("publish key for %q: %w", req.Email, err)
	}

	emailHash := publishKeyHashEmail(req.Email)
	uc.logger.Info("publish key: published successfully", map[string]interface{}{
		"email":      req.Email,
		"email_hash": emailHash,
	})

	return &PublishKeyResponse{
		EmailHash: emailHash,
		Rotated:   resp.Rotated,
		Rebound:   resp.Rebound,
	}, nil
}

// publishKeyHashEmail returns the SHA-256 hex of the lowercase-trimmed email.
func publishKeyHashEmail(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(h[:])
}
