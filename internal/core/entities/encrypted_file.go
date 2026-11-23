package entities

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EncryptionMethod represents how a file was encrypted
type EncryptionMethod string

const (
	MethodX25519     EncryptionMethod = "x25519-hkdf-aes256"
	MethodPassphrase EncryptionMethod = "passphrase-aes256" // #nosec G101 -- algorithm identifier constant, not a credential
	MethodSharedKey  EncryptionMethod = "sharedkey-aes256"
)

// FormatVersion is the container version byte (docs/format-spec.md). It is
// the only version: 0x01 and 0x02 are retired and fail with "unsupported
// version".
const FormatVersion uint8 = 3

// Container constants (docs/format-spec.md).
const (
	// KDFArgon2id is the method-3 "kdf" header value.
	KDFArgon2id = "argon2id"
	// MaxRecipients bounds the method-2 recipient blocks of a header.
	MaxRecipients = 16
	// WrapCEKAAD is the AES-GCM AAD of a recipient block.
	WrapCEKAAD = "mdstn-cipher/v2/wrap-cek"
	// FileSaltSize is the size of the method-3 Argon2id salt.
	FileSaltSize = 16
	// HeaderMACSize is the size of the header MAC at the start of the body.
	HeaderMACSize = 32
)

// KDFParams holds the Argon2id parameters of a method-3 header: memory M in
// KiB, T iterations, and P lanes.
type KDFParams struct {
	M, T, P uint32
}

// FileKDFParams is the only parameter set that the format accepts, so that a
// hostile file cannot choose the KDF cost.
var FileKDFParams = KDFParams{M: 65536, T: 3, P: 4}

// RecipientBlock represents a single recipient entry in a method-2 .mdstn
// file header. Blocks name no recipient: a decryptor finds its block by trial.
type RecipientBlock struct {
	EphemeralPubKey string `json:"ephemeral_pub_key"` // base64-encoded 32-byte ephemeral X25519 public key
	Nonce           string `json:"nonce"`             // base64-encoded 12-byte AES-GCM nonce
	WrappedCEK      string `json:"wrapped_cek"`       // base64-encoded 48-byte wrapped CEK (32+16 tag)
}

// EncryptedFile represents the .mdstn container header:
// [magic][version][method][headerLen][headerJSON]. The body (header MAC, then
// the frames) follows the header.
type EncryptedFile struct {
	Version          uint8
	Method           EncryptionMethod
	Chunked          bool             // header JSON "chunked": body framing selector (normative — MUST be present in every serialized header)
	Salt             []byte           // method 3: 16-byte Argon2id salt
	KDF              string           // method 3: KDFArgon2id
	KDFParams        KDFParams        // method 3: exactly FileKDFParams
	Recipients       []RecipientBlock // method 2: 1 to MaxRecipients blocks
	PolicyID         string           // method 5: shared-key policy ID
	OriginalFilename string
	EncryptedAt      time.Time
}

// DecodeHeaderBase64 decodes a base64 header value with the strict rules of
// the format: RFC 4648 standard alphabet with padding, zero padding bits, and
// no CR or LF (Go's decoder skips CR and LF, so they are checked first).
func DecodeHeaderBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("base64 value contains CR or LF")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// Validate checks the header rules of the format: the version, 1 to 16
// complete recipient blocks for method 2, the fixed Argon2id parameters for
// method 3, and a policy ID for method 5.
func (ef *EncryptedFile) Validate() error {
	if ef.Version != FormatVersion {
		return fmt.Errorf("unsupported version: %d (supported: %d)", ef.Version, FormatVersion)
	}
	if err := ValidOriginalFilename(ef.OriginalFilename); err != nil {
		return err
	}
	if !ef.EncryptedAt.IsZero() && ef.EncryptedAt.Unix() < 0 {
		return errors.New("encrypted_at is before 1970")
	}
	if ef.Method == "" {
		return errors.New("encryption method is required")
	}
	if ef.Method != MethodX25519 && len(ef.Recipients) > 0 {
		return errors.New("recipients are only valid for the X25519 method")
	}
	if ef.Method != MethodPassphrase && (len(ef.Salt) > 0 || ef.KDF != "" || ef.KDFParams != (KDFParams{})) {
		return errors.New("kdf fields are only valid for the passphrase method")
	}
	if ef.Method != MethodSharedKey && ef.PolicyID != "" {
		return errors.New("policy_id is only valid for the shared-key method")
	}

	switch ef.Method {
	case MethodX25519:
		if len(ef.Recipients) == 0 || len(ef.Recipients) > MaxRecipients {
			return fmt.Errorf("X25519 header needs 1 to %d recipient blocks, got %d", MaxRecipients, len(ef.Recipients))
		}
		for i, block := range ef.Recipients {
			if _, err := block.Decode(); err != nil {
				return fmt.Errorf("recipient block %d: %w", i, err)
			}
		}
	case MethodPassphrase:
		if ef.KDF != KDFArgon2id {
			return fmt.Errorf("passphrase header: kdf %q, want %q", ef.KDF, KDFArgon2id)
		}
		if ef.KDFParams != FileKDFParams {
			return fmt.Errorf("passphrase header: kdf parameters m=%d t=%d p=%d, want m=%d t=%d p=%d",
				ef.KDFParams.M, ef.KDFParams.T, ef.KDFParams.P, FileKDFParams.M, FileKDFParams.T, FileKDFParams.P)
		}
		if len(ef.Salt) != FileSaltSize {
			return fmt.Errorf("passphrase header: salt is %d bytes, want %d", len(ef.Salt), FileSaltSize)
		}
	case MethodSharedKey:
		if ef.PolicyID == "" {
			return errors.New("shared-key header needs policy_id")
		}
	default:
		return errors.New("unsupported encryption method")
	}
	return nil
}

// DecodedRecipientBlock is a recipient block with its base64 members decoded.
type DecodedRecipientBlock struct {
	EphemeralPubKey, Nonce, WrappedCEK []byte
}

// Decode decodes the base64 members of the block with DecodeHeaderBase64 and
// checks their sizes: 32, 12, and 48 bytes.
func (b RecipientBlock) Decode() (DecodedRecipientBlock, error) {
	var out DecodedRecipientBlock
	for _, field := range []struct {
		name, value string
		size        int
		dst         *[]byte
	}{
		{"ephemeral_pub_key", b.EphemeralPubKey, 32, &out.EphemeralPubKey},
		{"nonce", b.Nonce, 12, &out.Nonce},
		{"wrapped_cek", b.WrappedCEK, 48, &out.WrappedCEK},
	} {
		raw, err := DecodeHeaderBase64(field.value)
		if err != nil {
			return DecodedRecipientBlock{}, fmt.Errorf("%s: invalid base64: %w", field.name, err)
		}
		if len(raw) != field.size {
			return DecodedRecipientBlock{}, fmt.Errorf("%s is %d bytes, want %d", field.name, len(raw), field.size)
		}
		*field.dst = raw
	}
	return out, nil
}
