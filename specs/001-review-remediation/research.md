# Research: Review Remediation

All facts cite the tree at `835a6a6`. Items marked [INFERENCE] were not executed.

## R1. v1 stream hardening (FR-001, FR-002, FR-007)

- **Decision**: Apply the review patch to `internal/adapters/crypto/aes.go`. Add
  `streamChunkNonce()`. Reject an on-wire nonce that differs from the derived nonce. Reject
  `chunkLen > 64 KiB + 16` before `make`. Also require the end of input after the terminator.
- **Rationale**: spec §5 already defines the derived nonce. The encoder always writes it
  (`aes.go:146-160`). Principle III allows a stricter v1 decoder in this case.
- **Verified**: the patch passed the full suite in a copy of the tree. Swap, repeat, and remove
  failed before the patch and passed after it.
- **Change to the patch**: its oversized-length case passes before the fix too, because `ReadFull`
  fails after the 4 GiB allocation. The new test reads from a source that has only the 28 input
  bytes, and it requires `runtime.MemStats.TotalAlloc` to grow by less than 1 MiB.
- **Alternatives**: ignore the on-wire nonce and always use the derived nonce. Rejected: a frame
  with a wrong on-wire nonce must fail, not decrypt silently.

## R2. Staged output (FR-003, FR-004, FR-005, FR-019)

- **Decision**: change the internal port in `internal/core/usecases/ports.go:206-213`:

  ```go
  type StagedWriter interface {
      io.Writer
      Commit() error // fsync, close, rename to the final path
      Abort() error  // close and remove the temporary file; idempotent
  }
  WriteStream(path string) (StagedWriter, error)
  ```

  Every usecase error path calls `Abort()`. Only the success path calls `Commit()`. `WriteFile`
  uses the same staging internally.
- **Temporary name**: `os.CreateTemp(dir, "."+base+".*.mdstn-partial")`. `CreateTemp` uses
  `O_EXCL` and a random name, so a planted symlink is not followed.
- **Cleanup**: `CleanupStaleTempFiles` scans only `~/.mdstn` today (`cmd/root.go:65-67`). Staged
  files are next to the output, so that scan never finds them. The new `WriteStream` and
  `WriteFile` first remove `*.mdstn-partial` files older than 1 hour in the output directory
  (best effort, logged at WARN). The startup scan of `~/.mdstn` stays.
- **Cancellation**: commands use `context.Background()` (`cmd/*_cobra.go`). They change to
  `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)`, so that Ctrl-C reaches the
  `ctx.Err()` checks in the stream loops and the error path calls `Abort()`.
- **Public surface**: `FileHandler` is not re-exported by `pkg/cipherports`. This change is
  internal. The fakes in `encrypt_file_test.go:122-167` change to the new interface.
- **Alternatives**: keep `io.WriteCloser` with a type assertion for `Abort` (the review patch).
  Rejected: an implementation without `Abort` still publishes on failure.

## R3. Container version `0x03` ("format v2") (FR-006, FR-022 to FR-027)

- **Version byte**: `0x03`. Spec line 36 says that a pre-release "v2" was retired, and code
  comments say "streaming path (version 2)" (`encrypt_file.go:124,297,458`). A new meaning for
  `0x02` could make an old pre-release file parse. Governance item 2 changes to "next unused
  version byte".
- **AAD rule**: unchanged. `headerAAD = bytes[0 : 8+HeaderLen]`, including magic and version
  (`mdstn_format.go:11`). Thus a version-byte change (downgrade or upgrade) fails authentication.
- **Stream framing (STREAM construction, Hoang et al. 2015)**:

  ```
  body    = base_nonce(12) || frame_0 || ... || frame_n || u32be(0)
  frame_i = u32be(len_i) || ct_i            # no on-wire chunk nonce
  nonce_i = base_nonce XOR (0x00000000 || u64be(i))
  aad_i   = headerAAD || u64be(i) || u8(final_i)
  ```

  - Non-final chunks hold exactly 65536 plaintext bytes. The final chunk holds 0 to 65536 bytes.
    An empty plaintext is one final chunk of 0 bytes. Thus `len_i` is never 0, and a stream has
    at least one frame.
  - The encoder reads one chunk ahead to know `final`.
  - The decoder reads `frame_i`, then the next `u32`. If it is 0, `frame_i` is final. It then
    requires the end of input. A non-final frame with a plaintext size other than 65536 fails.
  - Truncation at a boundary: the last remaining frame was sealed with `final=0`. With a forged
    terminator it is opened with `final=1`, so it fails. Without a terminator, EOF fails.
- **Single frame** (`chunked=false`): `body = nonce(12) || ct`, `aad = headerAAD`. GCM already
  detects truncation of one frame.
- **Recipient key wrap (all method-2 files, 1 to 16 recipients)**:

  ```
  shared = X25519(eph_priv, R_pub)            # reject all-zero output
  kek    = HKDF-SHA256(ikm=shared, salt=eph_pub || R_pub, info="mdstn-cipher/v2/wrap", L=32)
  block  = { ephemeral_pub_key, nonce(12), wrapped_cek(48) }  # AAD "mdstn-cipher/v2/wrap-cek"
  ```

  This is the age X25519 recipient construction. The single-recipient v1 form
  (`key_id`, `recipient_key_id`, `encrypted_data`) has no v2 equivalent: one recipient is one
  block. "Encrypt for self" is one block for the default key.
- **Recipient privacy**: v2 blocks carry no `fingerprint_hint`, `key_id`, or `recipient_key_id`.
  The decoder tries each block with each usable local X25519 key: the default key first, then the
  other non-expired keys in the order of last use. A block fails cheaply (one X25519 and one GCM
  open). The cost is the private-key unwrap per local key (Argon2id KEK, cached by the session
  store). [INFERENCE] With 1 to 3 keys per user this is acceptable. The spec states the cost.
- **File-password KDF**: Argon2id with the key-at-rest parameters (`argon2id.go`: m=65536 KiB,
  t=3, p=4, 32-byte output), salt 16 bytes. Header: `{"kdf":"argon2id","salt":..,"m":65536,
  "t":3,"p":4}`. The decoder accepts only this exact parameter set. This bounds the KDF cost of a
  hostile file, and a future change of parameters needs a new version.
- **Method 5**: the Go core does not encrypt method 5, and `DecryptFile` rejects it
  (`decrypt_file.go:108-110`). The v2 spec defines method 5 with the v2 framing for other
  implementations. A v2 vector for method 5 is generated at the crypto layer.
- **Alternatives**: final flag in the nonce (age: 11-byte counter + flag byte, per-file key).
  Rejected: method 5 reuses one policy key across files, so v2 keeps a random base nonce, and the
  AAD carries the index and the flag.

## R4. Crypto port changes (Principle IV)

`CryptoEngine` is public (`pkg/cipherports/ports.go` alias block). Changes:

| Method | Change |
|---|---|
| `EncryptStream(ctx, src, dst, key, aad)` | Same signature. Writes v2 framing only. |
| `DecryptStream(ctx, src, dst, key, aad)` | Adds `version uint8`. Reads v1 and v2 framing. |
| `WrapCEK(cek, recipientPub, aad)` | Same signature. Uses the v2 KDF only. |
| `UnwrapCEK(..., privateKey, aad)` | Adds `version uint8`. v1 or v2 KDF. |
| `DeriveFileKeyArgon2id(password, salt)` | New. v2 method 3. |

The v1 stream encoder moves to a `_test.go` file in package `crypto`. Tests and the vector
generator (`generate_vectors_test.go` is `package crypto`) use it. Production code cannot write v1.
Justification: a stub-free, version-aware port. This ships with a minor version bump (`v0.3.0`).

## R5. Error classes and exit codes (FR-013, FR-014)

- **Decision**: add `entities.ErrWrongPassword` ("wrong file password, or the file is damaged").
  Add `entities.ChunkAuthError{Index uint64}` (implements `error`, `Is(ErrHeaderAuthFailed)`).
  Method 3: a failure of chunk 0 or of the single frame → `ErrWrongPassword`. A failure of a later
  chunk → `ErrHeaderAuthFailed` (the password was proven correct by chunk 0).
- **Exit mapping**: `cmd.ExitCode(err) int` with `errors.Is`: `ErrHeaderAuthFailed` → 2,
  `ErrNotARecipient` → 3, `ErrWrongPassword` → 4, other errors → 1. `main.go` calls
  `os.Exit(cmd.ExitCode(err))`. `cmd/encrypt.go:121` returns the error, it does not exit.
- **Alternatives**: add a key-check value to v2 method 3, to separate a wrong password from
  tampering. Rejected: it gives an offline password oracle with no gain over chunk 0.

## R6. Non-interactive inputs (FR-008, FR-009)

- `cmd/encrypt.go:96` prompts only when `passphrase == "" && forEmail == "" &&
  len(recipients) == 0` (recipients from `--recipient` and `--recipient-key`).
- New flags: `--password-file <path|->` on `encrypt` and `decrypt`. `--key-passphrase-file
  <path|->` on `decrypt`, `encrypt`, and `keys create`. One trailing newline is removed. Each is
  mutually exclusive with its inline flag. `MDSTN_KEY_PASSPHRASE` stays (`cmd/keys.go`).

## R7. `--recipient-key` (FR-010, FR-012)

- Value: standard base64 of 32 bytes, or a path to a file whose trimmed content is that base64.
  Rule: if the value decodes to exactly 32 bytes, it is a key, else it is a path.
- Validation before any output: length 32, and a trial X25519 with a random scalar must not give
  the all-zero output (low-order points). Failure → usage error (exit 1).
- Fingerprint: `cipher.Fingerprint` (SHA-256 hex, `pkg/cipher/fingerprint.go`) for display only.

## R8. SDK (FR-011, FR-018)

- **No database**: `cipher.InMemory` (`":memory:"`) as `Config.DBPath`. The driver is
  `modernc.org/sqlite` (`go.mod:10`). `sql.Open` at `identity_key_repo.go:22` needs
  `SetMaxOpenConns(1)` for `:memory:`, because each pool connection gets its own database.
  [INFERENCE] Verify with a test.
- **Streams**: the stubs take no recipients (`pkg/cipher/encrypt.go:125-133`), so they cannot work.
  New signatures:

  ```go
  func (c *Client) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, in EncryptStreamInput) error
  func (c *Client) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, in DecryptStreamInput) (*DecryptStreamResult, error)
  ```

  Streams always use `chunked=true`. The usecases get reader/writer cores
  (`EncryptFile.EncryptStream`, `DecryptFile.DecryptStream`). The file `Execute` methods wrap
  them with `ReadStream` and `StagedWriter`.
- **Header from a reader**: `DecryptFile.Execute` reads the whole file into memory
  (`decrypt_file.go:77`). A new `FileEncoder.DecodeHeader(r io.Reader)` reads 8 bytes, then
  `HeaderLen` bytes (bounded by `uint16`). The file path then streams too.

## R9. Lint, CI, docs (FR-015 to FR-017, FR-020, FR-021)

- golangci-lint 2.15.0 is installed. Set `linters.settings.errcheck.check-blank: true`. The 45
  non-test discards (inventory in `local://scout-usecases.md` §8) are handled as follows:
  - The 9 stream error paths change to `Abort()`, and the error is joined.
  - The `keyRepo.Update` usage counters (4) are logged at WARN.
  - The `MarkHidden`/`MarkFlagRequired` calls (4) panic on error in `init`, because a wrong flag
    name is a programming error.
  - The other best-effort cleanups get `//nolint:errcheck // best-effort: <reason>`.
  - `encrypt_file.go:350` `_ = wrapNonce` is removed (dead value).
- V3: `tests/external-sdk/main.go:19` uses `rand.Text()` (Go 1.24+) for the password. The scan
  regex stays as it is.
- Vectors: the generator writes a fixture only if the file does not exist. Thus the existing
  fixtures stay byte-identical. New: `v1-passphrase-chunked` (v1 stream, 3 chunks + partial), and
  v2 vectors for each method and framing. `vectors_conformance_test.go` learns both versions and
  stream bodies.
