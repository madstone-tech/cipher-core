package cipher

import (
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// MdstnFile is the in-memory representation of a .mdstn encrypted container.
// Version is always 3 (0x03, the one container format); see
// docs/format-spec.md §Container Version.
type MdstnFile = entities.EncryptedFile

// MdstnEncoder encodes and decodes .mdstn containers (version 0x03 only).
type MdstnEncoder = usecases.FileEncoder

// NewMdstnEncoder returns a conforming encoder.
func NewMdstnEncoder() MdstnEncoder {
	return crypto.NewFileEncoder()
}

// EncryptionMethod identifies the scheme a container was produced with.
type EncryptionMethod = entities.EncryptionMethod

// KeyType names an identity key's algorithm. X25519 is the only type this
// library generates.
type KeyType = entities.KeyType

// KeyTypeX25519 is the sole generated key type.
const KeyTypeX25519 = entities.KeyTypeX25519

// Encryption methods (auto-detected on decrypt — callers never select).
const (
	MethodX25519     = entities.MethodX25519
	MethodPassphrase = entities.MethodPassphrase
	MethodSharedKey  = entities.MethodSharedKey
)
