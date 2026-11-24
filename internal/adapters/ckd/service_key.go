package ckd

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// The hosted directory's response signing key, pinned per FR-006 (v1 ships it
// as build-time constants; per-profile pin storage joins when the service
// announces a second key id). Source: ckd-server docs/ckd-service-key.md,
// key id kd-2026-11.
const (
	// KDServiceKeyID is the pinned signature key id (X-Mdstn-Kd-Keyid).
	KDServiceKeyID = "kd-2026-11"

	// KDServicePublicKey is the pinned ed25519 public half, base64-std,
	// 32 bytes (X-Mdstn-Kd-Signature verification key).
	KDServicePublicKey = "gqd2RnaBd5ZShK1AIVk5KGMzIemiQ+K2OPF3CLIASh8="
)

// kdSignedHeaders are the response headers the verification reads.
const (
	HeaderSignature = "X-Mdstn-Kd-Signature"
	HeaderKeyID     = "X-Mdstn-Kd-Keyid"
)

// pinnedKDServiceKey decodes the pinned public key once.
func pinnedKDServiceKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(KDServicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode pinned CKD service public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned CKD service public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// kdCoveredContent builds the signature input: email_hash + "\n" + raw body
// (contract C3: covered content is over the exact bytes the server sent).
func kdCoveredContent(emailHash string, rawBody []byte) []byte {
	return append(append([]byte(emailHash), '\n'), rawBody...)
}

// verifyKDResponse verifies the signed response: base64-std ed25519 over the
// covered content, with a constant-time key-id comparison (FR-006).
// keyID == "" (header absent) is an integrity failure; sig == "" likewise.
func verifyKDResponse(emailHash string, rawBody []byte, sigB64, keyID string) error {
	if sigB64 == "" || keyID == "" {
		return fmt.Errorf("%w: missing %s or %s header", entities.ErrKDIntegrity, HeaderSignature, HeaderKeyID)
	}
	// Key id check is constant-time (FR-006): equal-length compare on the
	// ASCII ids, then a normal equality for the (constant) pinned id.
	if subtle.ConstantTimeCompare([]byte(keyID), []byte(pinnedVerificationID())) != 1 {
		return fmt.Errorf("%w: response signed under unrecognized key id %q (pinned %q) — the directory service key may have rotated; verify with the operator before trusting lookups", entities.ErrKDIntegrity, keyID, pinnedVerificationID())
	}

	pub, err := pinnedVerificationKey()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: signature header is not base64: %v", entities.ErrKDIntegrity, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", entities.ErrKDIntegrity, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, kdCoveredContent(emailHash, rawBody), sig) {
		return fmt.Errorf("%w: response signature does not verify", entities.ErrKDIntegrity)
	}
	return nil
}
