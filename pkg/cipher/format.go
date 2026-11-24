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

// RecipientBlock is one per-recipient header entry of a method-2 container
// (base64 ephemeral public key, nonce, wrapped CEK). Consumers outside the
// module construct these to build method-2 headers via MdstnFile.Recipients;
// without this alias an external module cannot name the field's element type.
type RecipientBlock = entities.RecipientBlock

// WrapCEKAAD is the AES-GCM AAD of a recipient block
// ("mdstn-cipher/v2/wrap-cek"); pass it to WrapCEK/UnwrapCEK exactly as the
// core does — an AAD mismatch is indistinguishable from tampering.
const WrapCEKAAD = entities.WrapCEKAAD

// KDFArgon2id is the method-3 "kdf" header value; FileKDFParams is the only
// accepted Argon2id parameter set. Consumers writing method-3 headers need
// both to produce a conforming header.
const KDFArgon2id = entities.KDFArgon2id

// FileKDFParams is the fixed method-3 Argon2id parameter set (m=65536, t=3,
// p=4): a hostile header cannot choose different KDF costs.
var FileKDFParams = entities.FileKDFParams

// FormatVersion is the container version byte, always 3 (0x03).
const FormatVersion = entities.FormatVersion

// HeaderMACSize is the size of the 32-byte header MAC that starts the body.
const HeaderMACSize = entities.HeaderMACSize

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
