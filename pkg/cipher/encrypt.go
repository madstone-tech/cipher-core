package cipher

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// EncryptInput specifies an encryption operation. The intent model follows the
// SDK's design rule: the caller states intent (for me / for email / with
// passphrase), never an algorithm.
type EncryptInput struct {
	// FilePath is the source file to encrypt. Required.
	FilePath string

	// RecipientEmail encrypts for one recipient resolved via CKD (TOFU).
	RecipientEmail string

	// Recipients encrypts for multiple recipients (multi-recipient KEM-DEM).
	// Takes precedence over RecipientEmail when both are set.
	Recipients []Recipient

	// Passphrase encrypts with a file password (Argon2id) instead of a key.
	Passphrase string

	// no key exists and "for me" encryption auto-creates one) and for
	// KEK unwrapping. Required only on those paths.
	KeyPassphrase string

	// OutputPath overrides the default <FilePath>.mdstn destination. An
	// explicit path replaces an existing file, but never the input itself.
	// The default path never replaces a file unless Overwrite: then Encrypt
	// fails with an error that matches ErrAlreadyExists.
	OutputPath string

	// Overwrite allows the default output path to replace an existing file.
	Overwrite bool
}

// Recipient identifies an encryption target by public key.
type Recipient struct {
	// PublicKey is the 32-byte X25519 public key.
	PublicKey []byte
	// Fingerprint is the SHA-256 fingerprint, for display only (files store no recipient identifier).
	Fingerprint string
}

// EncryptFileResult is the outcome of an encryption operation.
type EncryptFileResult struct {
	// OutputPath is where the .mdstn container was written.
	OutputPath string
	// Method is the encryption method used (X25519 / Passphrase / MultiX25519).
	Method EncryptionMethod
	// Fingerprint identifies the key used (empty for passphrase method).
	Fingerprint string
	// RecoveryMnemonic is non-empty only on first-run key generation with
	// JSON semantics (SDK surface always populates it when a key is created).
	RecoveryMnemonic string
}

// Encrypt encrypts a file per the input's intent. Exactly one intent must be
// set: RecipientEmail, Recipients, or Passphrase — or none, which encrypts
// for the caller's default key ("for me").
func (c *Client) Encrypt(ctx context.Context, in EncryptInput) (*EncryptFileResult, error) {
	if err := validateRecipients(in.Recipients); err != nil {
		return nil, fmt.Errorf("cipher: encrypt: %w", err)
	}
	resp, err := c.encryptFile(in.KeyPassphrase).Execute(ctx, &usecases.EncryptFileRequest{
		FilePath:       in.FilePath,
		RecipientEmail: in.RecipientEmail,
		Recipients:     toUsecaseRecipients(in.Recipients),
		Passphrase:     in.Passphrase,
		OutputPath:     in.OutputPath,
		Overwrite:      in.Overwrite,
		JSONOutput:     true, // SDK mode: never prompt; return mnemonic in response
	})
	if err != nil {
		return nil, fmt.Errorf("cipher: encrypt: %w", err)
	}
	return &EncryptFileResult{
		OutputPath:       resp.OutputPath,
		Method:           resp.Method,
		Fingerprint:      resp.Fingerprint,
		RecoveryMnemonic: resp.RecoveryMnemonic,
	}, nil
}

// DecryptInput specifies a decryption operation.
type DecryptInput struct {
	// FilePath is the .mdstn container to decrypt. Required.
	FilePath string

	// Passphrase is for passphrase-encrypted files.
	Passphrase string

	// RecoveryPassphrase unwraps the KEK for key-based files (headless mode;
	// when empty the SDK falls back to any active in-memory session).
	RecoveryPassphrase string

	// OutputPath is the destination. An explicit path replaces an existing
	// file, but never the input file itself. When it is empty, the output path
	// is FilePath without ".mdstn" (else FilePath + ".decrypted"); the header's
	// original_filename is never used as a path (see the result's
	// OriginalFilename). That default never replaces an existing file unless
	// Overwrite: then Decrypt fails with an error that matches
	// ErrAlreadyExists (and fs.ErrExist).
	OutputPath string

	// Overwrite allows the default output path to replace an existing file.
	Overwrite bool
}

// DecryptFileResult is the outcome of a decryption operation.
type DecryptFileResult struct {
	OutputPath string
	Method     EncryptionMethod
	// Version is the container version byte of the file (0x03).
	Version uint8
	// OriginalFilename is the sender's informational name from the header
	// (a safe base name, or ""). It was not used for OutputPath.
	OriginalFilename string
}

// Decrypt decrypts a .mdstn container. The method is auto-detected from the
// container header — no algorithm selection.
func (c *Client) Decrypt(ctx context.Context, in DecryptInput) (*DecryptFileResult, error) {
	resp, err := c.decryptFile(in.RecoveryPassphrase).Execute(ctx, &usecases.DecryptFileRequest{
		FilePath:           in.FilePath,
		Passphrase:         in.Passphrase,
		RecoveryPassphrase: in.RecoveryPassphrase,
		OutputPath:         in.OutputPath,
		Overwrite:          in.Overwrite,
	})
	if err != nil {
		return nil, fmt.Errorf("cipher: decrypt: %w", err)
	}
	return &DecryptFileResult{
		OutputPath:       resp.OutputPath,
		Method:           resp.Method,
		Version:          resp.Version,
		OriginalFilename: resp.OriginalFilename,
	}, nil
}

// EncryptStreamInput specifies a stream encryption. Set exactly one intent:
// Recipients, RecipientEmail, or Passphrase. Set none of them to encrypt
// for the default key of the caller ("for me").
type EncryptStreamInput struct {
	// Recipients encrypts for one or more raw X25519 public keys.
	// It has precedence over RecipientEmail.
	Recipients []Recipient

	// RecipientEmail encrypts for one recipient that CKD resolves (TOFU).
	RecipientEmail string

	// Passphrase encrypts with a file password.
	Passphrase string

	// KeyPassphrase unwraps the default key for "for me" encryption.
	KeyPassphrase string

	// OriginalFilename is stored in the header. It is optional and
	// informational: decryptors show it but never use it as a path. When it is
	// set, it MUST be a safe base name (not "." or "..", at most 255 bytes, no
	// "/", "\\", ":", control or invisible character); otherwise EncryptStream
	// fails with ErrInvalidInput before it writes anything.
	OriginalFilename string
}

// DecryptStreamInput specifies a stream decryption.
type DecryptStreamInput struct {
	// Passphrase is the file password of a passphrase-encrypted stream.
	Passphrase string

	// RecoveryPassphrase unwraps the KEK for a key-based stream. When it is
	// empty, the SDK uses an active in-memory session, if one exists.
	RecoveryPassphrase string
}

// DecryptStreamResult is the outcome of a stream decryption.
type DecryptStreamResult struct {
	// Method is the encryption method of the stream.
	Method EncryptionMethod
	// OriginalFilename is the filename stored in the header. It can be empty.
	OriginalFilename string
	// Version is the container version byte of the stream (0x03).
	Version uint8
}

// EncryptStream reads all of src and writes one chunked container (0x03)
// to dst. It does not create a file. It checks each Recipient.PublicKey
// before it writes to dst. An invalid key gives an error that matches
// ErrInvalidRecipientKey, and dst stays empty.
//
// For "for me" encryption (no intent set), a default key must exist.
// EncryptStream does not create one, because it cannot return the recovery
// phrase of a new key. If no default key exists, EncryptStream writes
// nothing to dst and returns an error that matches ErrNotFound. CreateKey
// does not make a default key. To make one and get its recovery phrase, call
// Encrypt once with no intent (EncryptFileResult.RecoveryMnemonic). Or
// encrypt to the public key from CreateKey with Recipients.
//
// If EncryptStream returns an error, dst can hold a partial container. The
// caller MUST discard dst.
func (c *Client) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, in EncryptStreamInput) error {
	if err := validateRecipients(in.Recipients); err != nil {
		return fmt.Errorf("cipher: encrypt stream: %w", err)
	}
	if in.Recipients == nil && in.RecipientEmail == "" && in.Passphrase == "" {
		if _, err := c.keyRepo.GetDefault(ctx); err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("cipher: encrypt stream: no default key: call Encrypt with no intent to create it and get its recovery phrase, or use Recipients with a key from CreateKey: %w", err)
			}
			return fmt.Errorf("cipher: encrypt stream: load default key: %w", err)
		}
	}
	if _, err := c.encryptFile(in.KeyPassphrase).EncryptStream(ctx, src, dst, &usecases.EncryptStreamRequest{
		Recipients:       toUsecaseRecipients(in.Recipients),
		RecipientEmail:   in.RecipientEmail,
		Passphrase:       in.Passphrase,
		OriginalFilename: in.OriginalFilename,
		JSONOutput:       true, // SDK mode: never prompt
	}); err != nil {
		return fmt.Errorf("cipher: encrypt stream: %w", err)
	}
	return nil
}

// DecryptStream reads one container (version 0x03) from src and writes
// its plaintext to dst. It does not create a file. DecryptStream
// authenticates each chunk before it writes the chunk to dst.
//
// If DecryptStream returns an error, dst can hold plaintext of earlier
// chunks. The caller MUST discard dst. The error matches
// ErrHeaderAuthFailed, ErrNotARecipient, or ErrWrongPassword with errors.Is.
func (c *Client) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, in DecryptStreamInput) (*DecryptStreamResult, error) {
	resp, err := c.decryptFile(in.RecoveryPassphrase).DecryptStream(ctx, src, dst, &usecases.DecryptStreamRequest{
		Passphrase:         in.Passphrase,
		RecoveryPassphrase: in.RecoveryPassphrase,
	})
	if err != nil {
		return nil, fmt.Errorf("cipher: decrypt stream: %w", err)
	}
	return &DecryptStreamResult{
		Method:           resp.Method,
		OriginalFilename: resp.OriginalFilename,
		Version:          resp.Version,
	}, nil
}

// toUsecaseRecipients converts the SDK recipient type to the usecase type.
func toUsecaseRecipients(rs []Recipient) []usecases.Recipient {
	if len(rs) == 0 {
		return nil
	}
	out := make([]usecases.Recipient, len(rs))
	for i, r := range rs {
		out[i] = usecases.Recipient{
			PublicKey:   r.PublicKey,
			Fingerprint: r.Fingerprint,
		}
	}
	return out
}
