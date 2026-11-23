package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory  = 64 * 1024 // 64 MB in KiB
	argon2Time    = 3
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// DeriveKeyArgon2id derives a 32-byte key from passphrase using Argon2id with a freshly
// generated 16-byte random salt. Returns the key and salt so the caller can store the salt
// for later decryption.
//
// Parameters (per the project constitution):
//   - memory: 64 MiB (65536 KiB)
//   - time:   3 iterations
//   - threads: 4
//   - keyLen:  32 bytes
//   - saltLen: 16 bytes
func (e *Engine) DeriveKeyArgon2id(passphrase string) (key []byte, salt []byte, err error) {
	if len(passphrase) == 0 {
		return nil, nil, fmt.Errorf("passphrase must not be empty")
	}

	salt = make([]byte, argon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate Argon2id salt: %w", err)
	}

	key = argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return key, salt, nil
}

// DeriveFileKeyArgon2id derives the method-3 (file password) file key from
// password and the 16-byte header salt: Argon2id with m=65536 KiB, t=3, p=4,
// and a 32-byte output. These are the key-at-rest parameters above and the
// only set that a header may name (entities.FileKDFParams).
func (e *Engine) DeriveFileKeyArgon2id(password string, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(salt) != argon2SaltLen {
		return nil, fmt.Errorf("invalid Argon2id salt size: expected %d bytes, got %d", argon2SaltLen, len(salt))
	}
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen), nil
}
