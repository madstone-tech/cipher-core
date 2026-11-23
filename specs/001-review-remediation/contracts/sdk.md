# Contract: SDK (`pkg/cipher`) and ports (`pkg/cipherports`)

This contract changes the public surface. Principle IV: it ships as minor version `v0.3.0`, with a
changelog entry for each item.

## `pkg/cipher`

```go
// InMemory, as Config.DBPath, keeps the key repository in memory. No file is created.
const InMemory = ":memory:"

type EncryptStreamInput struct {
    Recipients       []Recipient // or RecipientEmail, or Passphrase (exactly one intent; none = for me)
    RecipientEmail   string
    Passphrase       string
    KeyPassphrase    string
    OriginalFilename string      // stored in the header; optional
}

type DecryptStreamInput struct {
    Passphrase         string
    RecoveryPassphrase string
}

type DecryptStreamResult struct {
    Method           EncryptionMethod // same type as DecryptFileResult.Method
    OriginalFilename string
}

// EncryptStream reads all of src and writes one v2 chunked container to dst.
// "For me" (no intent set) needs an existing default key. EncryptStream does not create one.
func (c *Client) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, in EncryptStreamInput) error

// DecryptStream authenticates each chunk before it writes the chunk to dst.
// If it returns an error, dst can hold plaintext of earlier chunks: the caller MUST discard dst.
// Errors match ErrHeaderAuthFailed, ErrNotARecipient, or ErrWrongPassword with errors.Is.
func (c *Client) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, in DecryptStreamInput) (*DecryptStreamResult, error)
```

Removed: the old stub signatures `EncryptStream(ctx, src, dst) error` and
`DecryptStream(ctx, src, dst) error`.

New exported sentinels: `ErrWrongPassword`, `ErrInvalidRecipientKey`, `ErrHeaderAuthFailed`, and
`ErrNotARecipient` (aliases of the `entities` values).

"For me" rule: `EncryptStream` cannot return the recovery phrase of a new key. Thus it does not
create a default key. If no default key exists, it writes nothing to `dst` and returns an error
that matches `ErrNotFound`. `CreateKey` does not make a default key. To make the default key and
get its recovery phrase, call `Encrypt` once with no intent (`EncryptFileResult.RecoveryMnemonic`).
Alternatively, encrypt to the public key from `CreateKey` with `Recipients`.

`Recipient{PublicKey: pub}` with an invalid key (length, low-order point) fails before any output,
with an error that matches `ErrInvalidRecipientKey`.

## `pkg/cipherports` (alias of `usecases.CryptoEngine`)

```go
EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte) error         // writes v2 only
DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte, version uint8) error
WrapCEK(cek, recipientPublicKey, aad []byte) (ephemeralPubKey, nonce, wrappedCEK []byte, err error) // v2 KDF
UnwrapCEK(wrappedCEK, ephemeralPubKey, nonce, privateKey, aad []byte, version uint8) ([]byte, error)
DeriveFileKeyArgon2id(password string, salt []byte) ([]byte, error)                          // new
```

`FileEncoder` gains `DecodeHeader(r io.Reader) (*entities.EncryptedFile, []byte, error)`, which
returns the file and `headerAAD` and leaves `r` at the start of the body.

## Internal only (no public change)

`usecases.FileHandler.WriteStream(path) (StagedWriter, error)` with `Commit()` and `Abort()`.
