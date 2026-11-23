package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// HKDF info strings of the file-key schedule (docs/format-spec.md §Key
// schedule). The "v2" label names the format; the version byte is 0x03.
const (
	headerMACInfo = "mdstn-cipher/v2/header-mac"
	payloadInfo   = "mdstn-cipher/v2/payload"
)

// deriveFileSubkey returns HKDF-SHA256(ikm=fileKey, salt=nil, info, L=32).
func deriveFileSubkey(fileKey []byte, info string) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, fmt.Errorf("invalid file key size: expected 32 bytes, got %d", len(fileKey))
	}
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, fileKey, nil, []byte(info)), out); err != nil {
		return nil, fmt.Errorf("failed to derive %s key: %w", info, err)
	}
	return out, nil
}

// HeaderMAC returns the 32-byte header MAC of headerAAD for fileKey:
// HMAC-SHA256(HKDF-SHA256(fileKey, info="mdstn-cipher/v2/header-mac"), headerAAD).
// The body starts with it. It commits the header to one file key (HMAC-SHA256
// is collision resistant as a function of its key), so a file whose recipient
// blocks wrap different CEKs verifies for at most one of them.
func (e *Engine) HeaderMAC(fileKey, headerAAD []byte) ([]byte, error) {
	macKey, err := deriveFileSubkey(fileKey, headerMACInfo)
	if err != nil {
		return nil, err
	}
	defer clear(macKey)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(headerAAD) // hash.Hash.Write never returns an error
	return mac.Sum(nil), nil
}

// VerifyHeaderMAC reports whether headerMAC is the header MAC of headerAAD
// for fileKey. The comparison is constant time (hmac.Equal). A decryptor
// calls it before it decrypts any body byte.
func (e *Engine) VerifyHeaderMAC(fileKey, headerAAD, headerMAC []byte) (bool, error) {
	if len(headerMAC) != entities.HeaderMACSize {
		return false, fmt.Errorf("invalid header MAC size: expected %d bytes, got %d", entities.HeaderMACSize, len(headerMAC))
	}
	want, err := e.HeaderMAC(fileKey, headerAAD)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, headerMAC), nil
}

// DerivePayloadKey returns the key that seals the body frames:
// HKDF-SHA256(fileKey, info="mdstn-cipher/v2/payload").
func (e *Engine) DerivePayloadKey(fileKey []byte) ([]byte, error) {
	return deriveFileSubkey(fileKey, payloadInfo)
}
