package entities

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound indicates a resource was not found
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates a resource already exists
	ErrAlreadyExists = errors.New("already exists")

	// ErrInvalidInput indicates invalid input data
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnauthorized indicates unauthorized access
	ErrUnauthorized = errors.New("unauthorized")

	// ErrKeyExpired indicates the key has expired
	ErrKeyExpired = errors.New("key expired")

	// ErrDecryptionFailed indicates decryption failed
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrEncryptionFailed indicates encryption failed
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrKeyNotFound indicates the specified key was not found
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidKeyType indicates an invalid key type
	ErrInvalidKeyType = errors.New("invalid key type")

	// ErrCKDLookupFailed indicates CKD key lookup failed
	ErrCKDLookupFailed = errors.New("CKD key lookup failed")

	// ErrKeyChanged indicates a key has changed (TOFU violation)
	ErrKeyChanged = errors.New("key has changed - verify with recipient before proceeding")

	// ErrRecoveryAborted indicates recovery phrase confirmation was aborted
	ErrRecoveryAborted = errors.New("recovery phrase confirmation aborted")

	// ErrNotImplemented indicates a feature is stubbed for future implementation
	ErrNotImplemented = errors.New("not implemented")

	// ErrNoRecipients indicates no recipients were provided for multi-recipient encryption
	ErrNoRecipients = errors.New("at least one recipient is required")

	// ErrTooManyRecipients indicates the recipient count exceeds the soft cap
	ErrTooManyRecipients = errors.New("recipient count exceeds maximum of 16")

	// ErrNotARecipient indicates the file is not encrypted to any of the user's available keys
	ErrNotARecipient = errors.New("this file is not encrypted to any of your keys")

	// ErrHeaderAuthFailed indicates that the container failed authentication:
	// the header MAC does not verify with a file key that a recipient block
	// gave, or the body fails after the header MAC verified (tampered,
	// corrupted, or truncated).
	ErrHeaderAuthFailed = errors.New("this file's header failed authentication — it may be corrupted or tampered with")

	// ErrWrongPassword indicates that the header MAC of a file-password
	// (method 3) file does not verify with the key from the given password.
	// The header MAC is the key check, so a damaged header or header MAC gives
	// the same result.
	ErrWrongPassword = errors.New("wrong file password, or the file is damaged")

	// ErrInvalidRecipientKey indicates a recipient public key that is not a
	// canonical X25519 key: not 32 bytes, bit 255 set, u ≥ 2^255 − 19, or a
	// low-order point.
	ErrInvalidRecipientKey = errors.New("invalid recipient public key")
)

// ChunkAuthError reports that the stream body failed at chunk Index: a GCM
// failure, or a structural failure (length bound, truncation, trailing data,
// non-canonical final frame). The header MAC verified before the body, so
// every chunk failure is tampering: it matches ErrHeaderAuthFailed with
// errors.Is. errors.As recovers the index.
type ChunkAuthError struct {
	Index uint64
}

func (e *ChunkAuthError) Error() string {
	return fmt.Sprintf("chunk %d authentication failed", e.Index)
}

// Is makes errors.Is(err, ErrHeaderAuthFailed) true for a chunk failure.
func (e *ChunkAuthError) Is(target error) bool {
	return target == ErrHeaderAuthFailed
}
