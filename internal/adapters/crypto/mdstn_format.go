package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

const mdstMagic = "MDST"

// forbiddenFields are the members of the retired 0x01 header. A header (or,
// for fingerprint_hint, a recipient block) that has any of them, even with an
// empty value, fails to parse, for every method.
var forbiddenFields = []string{"key_id", "recipient_key_id", "ephemeral_pub_key", "nonce", "encrypted_data", "fingerprint_hint"}

// FileEncoder implements the FileEncoder interface
type FileEncoder struct{}

// NewFileEncoder creates a new file encoder
func NewFileEncoder() *FileEncoder {
	return &FileEncoder{}
}

// HeaderAADLength is the byte offset at which the container body begins:
// magic(4) + version(1) + method(1) + headerLen(2) + headerJSON(headerLen).
func HeaderAADLength(headerLen int) int64 { return int64(8 + headerLen) }

// EncodeHeader validates the file and serializes the container header:
// [magic][version=0x03][method][headerLen][headerJSON]. The body (header MAC,
// then the frames sealed with this header's bytes as AAD) is appended by the
// caller.
func (fe *FileEncoder) EncodeHeader(file *entities.EncryptedFile) ([]byte, error) {
	if err := file.Validate(); err != nil {
		return nil, fmt.Errorf("invalid encrypted file: %w", err)
	}
	headerJSON, err := json.Marshal(marshalHeader(file))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	return assembleHeader(file.Version, file.Method, headerJSON)
}

// assembleHeader writes magic | version | method byte | u16be(len) | headerJSON.
func assembleHeader(version uint8, method entities.EncryptionMethod, headerJSON []byte) ([]byte, error) {
	if len(headerJSON) > math.MaxUint16 {
		return nil, fmt.Errorf("header JSON is %d bytes, more than %d", len(headerJSON), math.MaxUint16)
	}
	var methodByte byte
	switch method {
	case entities.MethodX25519:
		methodByte = 2
	case entities.MethodPassphrase:
		methodByte = 3
	case entities.MethodSharedKey:
		methodByte = 5
	}
	out := make([]byte, 0, 8+len(headerJSON))
	out = append(out, mdstMagic...)
	out = append(out, version, methodByte)
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerJSON))) // #nosec G115 -- bounded by the check above
	return append(out, headerJSON...), nil
}

// EncodeHeaderPlusBody serializes the header and appends the encrypted body to
// the SAME buffer so callers write the container with a single atomic
// WriteFile (file atomicity for the in-memory path).
func (fe *FileEncoder) EncodeHeaderPlusBody(file *entities.EncryptedFile, body []byte) ([]byte, error) {
	headerBytes, err := fe.EncodeHeader(file)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(headerBytes)+len(body))
	out = append(out, headerBytes...)
	out = append(out, body...)
	return out, nil
}

// marshalHeader builds the header JSON members: the common members, and only
// the members of the file's method.
func marshalHeader(file *entities.EncryptedFile) map[string]any {
	header := map[string]any{
		"chunked":           file.Chunked,
		"original_filename": file.OriginalFilename,
	}
	// encrypted_at is optional: a zero time is omitted (its Unix value is
	// negative, and header numbers must be non-negative integers).
	if !file.EncryptedAt.IsZero() {
		header["encrypted_at"] = file.EncryptedAt.Unix()
	}
	switch file.Method {
	case entities.MethodX25519:
		blocks := make([]map[string]string, 0, len(file.Recipients))
		for _, b := range file.Recipients {
			blocks = append(blocks, map[string]string{
				"ephemeral_pub_key": b.EphemeralPubKey,
				"nonce":             b.Nonce,
				"wrapped_cek":       b.WrappedCEK,
			})
		}
		header["recipients"] = blocks
	case entities.MethodPassphrase:
		header["kdf"] = file.KDF
		header["salt"] = base64.StdEncoding.EncodeToString(file.Salt)
		header["m"] = file.KDFParams.M
		header["t"] = file.KDFParams.T
		header["p"] = file.KDFParams.P
	case entities.MethodSharedKey:
		header["policy_id"] = file.PolicyID
	}
	return header
}

// DecodeWithOffset decodes a .mdstn binary format to EncryptedFile and returns the
// raw header bytes (the AAD input: [0:8+headerLen]) and the byte offset at which
// the body (the header MAC) begins — the number of header bytes consumed.
func (fe *FileEncoder) DecodeWithOffset(data []byte) (*entities.EncryptedFile, []byte, int64, error) {
	file, headerAAD, err := fe.DecodeHeader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, 0, err
	}
	return file, headerAAD, int64(len(headerAAD)), nil
}

// Decode decodes the header of a .mdstn binary format to EncryptedFile.
func (fe *FileEncoder) Decode(data []byte) (*entities.EncryptedFile, error) {
	file, _, err := fe.DecodeHeader(bytes.NewReader(data))
	return file, err
}

// DecodeHeader reads exactly the container header from r: 8 bytes, then
// HeaderLen (at most 65535) bytes of JSON. It returns the file and headerAAD
// (the bytes read, [0:8+HeaderLen]) and leaves r at the start of the body.
// Only version 0x03 is valid; any other version byte (0x01 and 0x02 are
// retired) fails with "unsupported version" before the JSON is read.
func (fe *FileEncoder) DecodeHeader(r io.Reader) (*entities.EncryptedFile, []byte, error) {
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, nil, fmt.Errorf("file too short: minimum 8 bytes required: %w", err)
	}
	if string(prefix[:4]) != mdstMagic {
		return nil, nil, fmt.Errorf("invalid magic header: expected %s, got %q", mdstMagic, prefix[:4])
	}

	version := prefix[4]
	if version != entities.FormatVersion {
		return nil, nil, fmt.Errorf("unsupported version: %d (supported: %d)", version, entities.FormatVersion)
	}

	var method entities.EncryptionMethod
	switch prefix[5] {
	case 2:
		method = entities.MethodX25519
	case 3:
		method = entities.MethodPassphrase
	case 5:
		method = entities.MethodSharedKey
	default:
		return nil, nil, fmt.Errorf("unsupported method: %d", prefix[5])
	}

	headerLen := int(binary.BigEndian.Uint16(prefix[6:8]))
	headerAAD := make([]byte, 8+headerLen)
	copy(headerAAD, prefix[:])
	if _, err := io.ReadFull(r, headerAAD[8:]); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Decoded with encoding/json/v2 rather than v1: the header is attacker-
	// supplied and steers key selection before anything is authenticated (the
	// header MAC is checked later, once a file key exists), so it is parsed
	// under v2's stricter rules — duplicate members and invalid UTF-8 are
	// rejected instead of being silently resolved last-wins or replaced.
	// Unknown members stay permitted; the format relies on them for forward
	// compatibility. The Encode path stays on v1 to keep the emitted bytes
	// identical to the browser encoder (sorted members, no spaces).
	if err := checkHeaderJSON(headerAAD[8:]); err != nil {
		return nil, nil, err
	}
	var header map[string]any
	if err := jsonv2.Unmarshal(headerAAD[8:], &header); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	file := &entities.EncryptedFile{Version: version, Method: method}
	chunkedRaw, ok := header["chunked"]
	if !ok {
		return nil, nil, fmt.Errorf("missing chunked field")
	}
	chunked, ok := chunkedRaw.(bool)
	if !ok {
		return nil, nil, fmt.Errorf("chunked field must be a boolean")
	}
	file.Chunked = chunked

	if err := parseHeader(header, file); err != nil {
		return nil, nil, err
	}
	return file, headerAAD, nil
}

// parseHeader reads the header members into file and applies the header
// rules (entities.EncryptedFile.Validate). It runs before any key derivation,
// so a hostile header cannot choose the KDF cost.
func parseHeader(header map[string]any, file *entities.EncryptedFile) error {
	for _, key := range forbiddenFields {
		if _, ok := header[key]; ok {
			return fmt.Errorf("header has the retired field %q", key)
		}
	}
	var err error
	if file.OriginalFilename, err = optionalString(header, "original_filename"); err != nil {
		return err
	}
	if raw, ok := header["encrypted_at"]; ok {
		sec, ok := raw.(float64)
		if !ok || sec != math.Trunc(sec) {
			return fmt.Errorf("header: encrypted_at must be an integer")
		}
		file.EncryptedAt = time.Unix(int64(sec), 0)
	}

	switch file.Method {
	case entities.MethodX25519:
		blocks, ok := header["recipients"].([]any)
		if !ok {
			return fmt.Errorf("header: recipients must be an array")
		}
		if len(blocks) == 0 || len(blocks) > entities.MaxRecipients {
			return fmt.Errorf("header needs 1 to %d recipient blocks, got %d", entities.MaxRecipients, len(blocks))
		}
		file.Recipients = make([]entities.RecipientBlock, 0, len(blocks))
		for i, raw := range blocks {
			block, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("header: recipient block %d must be an object", i)
			}
			if _, ok := block["fingerprint_hint"]; ok {
				return fmt.Errorf("header: recipient block %d has the retired field \"fingerprint_hint\"", i)
			}
			var rb entities.RecipientBlock
			for _, f := range []struct {
				key string
				dst *string
			}{{"ephemeral_pub_key", &rb.EphemeralPubKey}, {"nonce", &rb.Nonce}, {"wrapped_cek", &rb.WrappedCEK}} {
				if *f.dst, err = optionalString(block, f.key); err != nil {
					return fmt.Errorf("header: recipient block %d: %w", i, err)
				}
			}
			file.Recipients = append(file.Recipients, rb)
		}
	case entities.MethodPassphrase:
		if file.KDF, err = optionalString(header, "kdf"); err != nil {
			return err
		}
		salt, err := optionalString(header, "salt")
		if err != nil {
			return err
		}
		if file.Salt, err = entities.DecodeHeaderBase64(salt); err != nil {
			return fmt.Errorf("header: invalid base64 for salt: %w", err)
		}
		for _, f := range []struct {
			key string
			dst *uint32
		}{{"m", &file.KDFParams.M}, {"t", &file.KDFParams.T}, {"p", &file.KDFParams.P}} {
			if *f.dst, err = requiredUint32(header, f.key); err != nil {
				return err
			}
		}
	case entities.MethodSharedKey:
		if file.PolicyID, err = optionalString(header, "policy_id"); err != nil {
			return err
		}
	}

	if err := file.Validate(); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}
	return nil
}

// optionalString returns the string member key of m ("" if absent). A
// present member of another type is an error.
func optionalString(m map[string]any, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("header: %s must be a string", key)
	}
	return s, nil
}

// requiredUint32 returns the integer member key of m, which must be present
// and fit a uint32.
func requiredUint32(m map[string]any, key string) (uint32, error) {
	raw, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("header: missing %s", key)
	}
	n, ok := raw.(float64)
	if !ok || n != math.Trunc(n) || n < 0 || n > math.MaxUint32 {
		return 0, fmt.Errorf("header: %s must be an unsigned 32-bit integer", key)
	}
	return uint32(n), nil
}
