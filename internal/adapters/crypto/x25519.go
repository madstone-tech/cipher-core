package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

const x25519KeySize = 32

// curve25519P is p = 2^255 - 19, little-endian.
var curve25519P = [x25519KeySize]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// ValidatePublicKey checks that pub is a canonical X25519 recipient public
// key (docs/format-spec.md §Canonical public keys): exactly 32 bytes, bit 255
// clear, u < 2^255 - 19 as a little-endian integer, and not a low-order point
// (a trial X25519 with a random scalar gives a non-zero shared secret). A
// non-canonical encoding names the same point as a canonical one but changes
// the wrap-key HKDF salt, so its owner could not decrypt the file. A failure
// matches entities.ErrInvalidRecipientKey.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != x25519KeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", entities.ErrInvalidRecipientKey, x25519KeySize, len(pub))
	}
	if pub[31]&0x80 != 0 {
		return fmt.Errorf("%w: bit 255 is set (non-canonical encoding)", entities.ErrInvalidRecipientKey)
	}
	if !lessThanP(pub) {
		return fmt.Errorf("%w: u is not below 2^255 - 19 (non-canonical encoding)", entities.ErrInvalidRecipientKey)
	}
	scalar := make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, scalar); err != nil {
		return fmt.Errorf("generate trial scalar: %w", err)
	}
	shared, err := curve25519.X25519(scalar, pub)
	clear(scalar)
	if err != nil {
		return fmt.Errorf("%w: %w", entities.ErrInvalidRecipientKey, err)
	}
	if subtle.ConstantTimeCompare(shared, make([]byte, x25519KeySize)) == 1 {
		return fmt.Errorf("%w: low-order point", entities.ErrInvalidRecipientKey)
	}
	clear(shared)
	return nil
}

// lessThanP reports whether the little-endian 32-byte u is below p. A public
// key is public, so the comparison need not be constant time.
func lessThanP(u []byte) bool {
	for i := x25519KeySize - 1; i >= 0; i-- {
		if u[i] != curve25519P[i] {
			return u[i] < curve25519P[i]
		}
	}
	return false
}

// ValidatePublicKey is the CryptoEngine form of the package ValidatePublicKey.
func (e *Engine) ValidatePublicKey(pub []byte) error { return ValidatePublicKey(pub) }

// EncryptX25519 encrypts plaintext for a recipient using X25519 ECDH + HKDF + AES-GCM
func (e *Engine) EncryptX25519(plaintext, recipientPublicKey, aad []byte) (ciphertext, ephemeralPubKey, nonce []byte, err error) {
	if len(recipientPublicKey) != x25519KeySize {
		return nil, nil, nil, fmt.Errorf("invalid recipient public key size: expected %d bytes", x25519KeySize)
	}

	// Generate ephemeral keypair
	ephemeralPrivKey := make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}

	ephemeralPubKey, err = curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral public key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := curve25519.X25519(ephemeralPrivKey, recipientPublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key using HKDF
	aesKey := make([]byte, 32)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("mdstn-cipher-x25519"))
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	// Encrypt with AES-GCM
	ciphertext, nonce, err = e.EncryptAES(plaintext, aesKey, aad)
	if err != nil {
		return nil, nil, nil, err
	}

	return ciphertext, ephemeralPubKey, nonce, nil
}

// DecryptX25519 decrypts ciphertext using X25519 ECDH + HKDF + AES-GCM.
// aad must match the value passed to EncryptX25519 exactly.
func (e *Engine) DecryptX25519(ciphertext, ephemeralPubKey, nonce, privateKey, aad []byte) (plaintext []byte, err error) {
	if len(ephemeralPubKey) != x25519KeySize {
		return nil, fmt.Errorf("invalid ephemeral public key size: expected %d bytes", x25519KeySize)
	}
	if len(privateKey) != x25519KeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d bytes", x25519KeySize)
	}

	// Perform ECDH
	sharedSecret, err := curve25519.X25519(privateKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key using HKDF
	aesKey := make([]byte, 32)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("mdstn-cipher-x25519"))
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	// Decrypt with AES-GCM
	plaintext, err = e.DecryptAES(ciphertext, aesKey, nonce, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// wrapInfo is the HKDF info of the recipient-block KEK; the HKDF salt is
// eph_pub || recipient_pub.
const wrapInfo = "mdstn-cipher/v2/wrap"

// x25519Shared computes X25519(scalar, point) and rejects an all-zero result
// (a low-order point), so no KEK is derived from a value that an attacker
// controls without a private key.
func x25519Shared(scalar, point []byte) ([]byte, error) {
	shared, err := curve25519.X25519(scalar, point)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	if subtle.ConstantTimeCompare(shared, make([]byte, x25519KeySize)) == 1 {
		return nil, fmt.Errorf("failed to compute shared secret: all-zero output (low-order point)")
	}
	return shared, nil
}

// deriveWrapKEK derives the 32-byte recipient-block KEK from the shared secret:
// HKDF-SHA256(ikm=shared, salt=eph_pub||recipient_pub, info=wrapInfo), which
// binds the ephemeral and the recipient public key (age X25519 construction).
func deriveWrapKEK(shared, ephemeralPubKey, recipientPubKey []byte) ([]byte, error) {
	salt := make([]byte, 0, 2*x25519KeySize)
	salt = append(salt, ephemeralPubKey...)
	salt = append(salt, recipientPubKey...)
	kek := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(wrapInfo)), kek); err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}
	return kek, nil
}

// WrapCEK encrypts a content encryption key (CEK) for a recipient with the
// wrap KDF (deriveWrapKEK) and AES-256-GCM. aad is the GCM AAD of the block:
// files MUST pass entities.WrapCEKAAD (the usecase does). The engine does not
// substitute it, so UnwrapCEK and WrapCEK treat aad the same way. The
// recipient key must be canonical (ValidatePublicKey). Returns the ephemeral
// public key (32 B), nonce (12 B), and wrapped CEK (48 B: ciphertext + tag).
func (e *Engine) WrapCEK(cek, recipientPublicKey, aad []byte) (ephemeralPubKey, nonce, wrappedCEK []byte, err error) {
	if len(cek) != 32 {
		return nil, nil, nil, fmt.Errorf("invalid CEK size: expected 32 bytes, got %d", len(cek))
	}
	if err := ValidatePublicKey(recipientPublicKey); err != nil {
		return nil, nil, nil, err
	}

	// Generate ephemeral keypair
	ephemeralPrivKey := make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}
	defer clear(ephemeralPrivKey)

	ephemeralPubKey, err = curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral public key: %w", err)
	}

	sharedSecret, err := x25519Shared(ephemeralPrivKey, recipientPublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(sharedSecret)

	kek, err := deriveWrapKEK(sharedSecret, ephemeralPubKey, recipientPublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(kek)

	wrappedCEK, nonce, err = e.EncryptAES(cek, kek, aad)
	if err != nil {
		return nil, nil, nil, err
	}
	return ephemeralPubKey, nonce, wrappedCEK, nil
}

// UnwrapCEK decrypts a wrapped CEK using the recipient's private key. The
// recipient public key in the KDF salt is derived from privateKey. aad must
// match the value passed at wrap time (entities.WrapCEKAAD).
func (e *Engine) UnwrapCEK(wrappedCEK, ephemeralPubKey, nonce, privateKey, aad []byte) (cek []byte, err error) {
	if len(ephemeralPubKey) != x25519KeySize {
		return nil, fmt.Errorf("invalid ephemeral public key size: expected %d bytes", x25519KeySize)
	}
	if len(privateKey) != x25519KeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d bytes", x25519KeySize)
	}

	recipientPubKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive recipient public key: %w", err)
	}

	sharedSecret, err := x25519Shared(privateKey, ephemeralPubKey)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret)

	kek, err := deriveWrapKEK(sharedSecret, ephemeralPubKey, recipientPubKey)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	return e.DecryptAES(wrappedCEK, kek, nonce, aad)
}

// GenerateX25519Keypair generates a new X25519 keypair
func (e *Engine) GenerateX25519Keypair() (publicKey, privateKey []byte, err error) {
	privateKey = make([]byte, x25519KeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	return publicKey, privateKey, nil
}
