package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2idKEKProvider derives key-encrypting keys from passphrases using Argon2id
// and wraps/unwraps private key material with AES-256-GCM.
type Argon2idKEKProvider struct{}

// NewArgon2idKEKProvider returns a new KEKProvider backed by Argon2id + AES-256-GCM.
func NewArgon2idKEKProvider() *Argon2idKEKProvider {
	return &Argon2idKEKProvider{}
}

// DeriveKEK derives a 32-byte KEK from passphrase and salt using Argon2id.
// Parameters per the project constitution: memory=64MB, time=3, threads=4.
func (p *Argon2idKEKProvider) DeriveKEK(passphrase string, salt []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	if len(salt) != argon2SaltLen {
		return nil, fmt.Errorf("salt must be exactly %d bytes, got %d", argon2SaltLen, len(salt))
	}
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return key, nil
}

// GenerateSalt returns 16 cryptographically random bytes for use as an Argon2id salt.
func (p *Argon2idKEKProvider) GenerateSalt() ([]byte, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// wrappedKeyAAD returns the additional authenticated data binding a wrapped key
// blob to its owning key ID: "mdstn-wrapped-key:<keyID>". This makes wrapped-key
// blobs non-transferable between keys (substituting one user's wrapped key for
// another's fails authentication) while the same key ID unwraps identically
// across storage backends (dual-storage design).
func wrappedKeyAAD(keyID string) []byte {
	return []byte("mdstn-wrapped-key:" + keyID)
}

// WrapKey encrypts privateKey using AES-256-GCM with kek as the key.
// AAD binds the blob to keyID (see wrappedKeyAAD).
// Returns nonce(12 bytes) || ciphertext (includes GCM auth tag).
func (p *Argon2idKEKProvider) WrapKey(privateKey []byte, kek []byte, keyID string) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(kek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, privateKey, wrappedKeyAAD(keyID))

	// Return nonce || ciphertext
	wrapped := make([]byte, len(nonce)+len(ciphertext))
	copy(wrapped, nonce)
	copy(wrapped[len(nonce):], ciphertext)
	return wrapped, nil
}

// UnwrapKey decrypts wrapped bytes (nonce || ciphertext) using AES-256-GCM with kek.
// AAD must bind the keyID the blob was wrapped with (see wrappedKeyAAD).
// Returns an error on authentication failure (wrong passphrase) or key-ID mismatch.
func (p *Argon2idKEKProvider) UnwrapKey(wrapped []byte, kek []byte, keyID string) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(kek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short: expected at least %d bytes, got %d", nonceSize, len(wrapped))
	}

	nonce := wrapped[:nonceSize]
	ciphertext := wrapped[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, wrappedKeyAAD(keyID))
	if err != nil {
		return nil, fmt.Errorf("key unwrap failed (wrong passphrase, corrupted data, or key-ID mismatch): %w", err)
	}
	return plaintext, nil
}

// ZeroKEK overwrites all bytes of kek with zeros.
func (p *Argon2idKEKProvider) ZeroKEK(kek []byte) {
	for i := range kek {
		kek[i] = 0
	}
}
