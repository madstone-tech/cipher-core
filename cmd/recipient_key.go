package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// maxRecipientKeyFileSize bounds a --recipient-key file: one base64 key plus
// whitespace.
const maxRecipientKeyFileSize = 4 << 10

// parseRecipientKey parses a --recipient-key value: standard base64 of
// exactly 32 bytes, else a path to a file whose trimmed content is that
// base64. The key must pass crypto.ValidatePublicKey. Every failure matches
// entities.ErrInvalidRecipientKey.
func parseRecipientKey(v string) ([]byte, error) {
	if key, ok := decodeKeyB64(v); ok {
		return validatedKey(key)
	}

	info, err := os.Stat(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is neither base64 of 32 bytes nor a readable file: %w", entities.ErrInvalidRecipientKey, v, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxRecipientKeyFileSize {
		return nil, fmt.Errorf("%w: %s is not a key file", entities.ErrInvalidRecipientKey, v)
	}
	data, err := os.ReadFile(v)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", entities.ErrInvalidRecipientKey, v, err)
	}
	key, ok := decodeKeyB64(strings.TrimSpace(string(data)))
	if !ok {
		return nil, fmt.Errorf("%w: %s does not hold base64 of 32 bytes", entities.ErrInvalidRecipientKey, v)
	}
	return validatedKey(key)
}

func decodeKeyB64(s string) ([]byte, bool) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != 32 {
		return nil, false
	}
	return key, true
}

func validatedKey(key []byte) ([]byte, error) {
	if err := crypto.ValidatePublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// rawKeyRecipients parses --recipient-key values into recipients. The
// fingerprint is the SHA-256 hex of the key (cipher.Fingerprint), for display.
func rawKeyRecipients(values []string) ([]usecases.Recipient, error) {
	recipients := make([]usecases.Recipient, 0, len(values))
	for _, v := range values {
		key, err := parseRecipientKey(v)
		if err != nil {
			return nil, fmt.Errorf("--recipient-key: %w", err)
		}
		sum := sha256.Sum256(key)
		recipients = append(recipients, usecases.Recipient{
			PublicKey:   key,
			Fingerprint: hex.EncodeToString(sum[:]),
		})
	}
	return recipients, nil
}
