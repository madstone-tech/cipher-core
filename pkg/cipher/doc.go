// Package cipher is the public SDK façade over Madstone Cipher's open core:
// zero-knowledge file encryption, X25519 key lifecycle with BIP39 recovery,
// and email-based key discovery (CKD).
//
// # Stability contract (v0)
//
// This package is documented as **v0**: breaking changes are allowed until
// 1.0 and are tracked in the repository changelog. The stable surface is the
// symbol list below; anything not on it is explicitly unstable.
//
// Stable symbols:
//
//	Client, Config, New, NewLocal, InMemory
//	Encrypt (EncryptInput), Decrypt (DecryptInput)
//	EncryptStream (EncryptStreamInput), DecryptStream (DecryptStreamInput)
//	CreateKey, ListKeys, GetKey, DeleteKey, AliasKey, ExportKey
//	LookupKey, PublishKey
//	RecoverFromMnemonic, DeriveFromMnemonic
//	EncryptFileResult, DecryptFileResult, DecryptStreamResult, KeyResult, KeyInfo
//	ErrHeaderAuthFailed, ErrNotARecipient, ErrWrongPassword, ErrInvalidRecipientKey
//
// The SDK reads and writes the one .mdstn container format, version byte
// 0x03 (docs/format-spec.md). Versions 0x01 and 0x02 are retired and fail
// with "unsupported version". Files produced by this SDK are decryptable by
// the mdstn-cipher CLI and any conforming implementation.
//
// # Usage
//
// The zero-config path uses an embedded SQLite store (default path
// ~/.mdstn/cipher.db):
//
//	client, err := cipher.NewLocal("")
//	// never swallow errors
//	res, err := client.Encrypt(ctx, cipher.EncryptInput{FilePath: "secret.pdf"})
//
// EncryptStream and DecryptStream use an io.Reader and an io.Writer. They do
// not create a file. DecryptStream authenticates each chunk before it writes
// the chunk to dst. If DecryptStream returns an error, dst can hold plaintext
// of earlier chunks. The caller MUST discard dst:
//
//	var pt bytes.Buffer
//	if _, err := client.DecryptStream(ctx, src, &pt, cipher.DecryptStreamInput{Passphrase: pw}); err != nil {
//		pt.Reset() // discard partial plaintext
//		return err
//	}
//
// Explicit-dependency construction lets callers inject their own stores,
// CKD directory URL, and logger:
//
//	client, err := cipher.New(cipher.Config{...})
//
// All operations are context-aware and constructor-injected; the package has
// no global state.
package cipher
