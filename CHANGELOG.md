# Changelog

## v0.3.2 (2026-11-24)

### Added

- `pkg/cipher` facade re-exports for first-class external container
  construction: `RecipientBlock`, `WrapCEKAAD`, `KDFArgon2id`,
  `FileKDFParams`, `FormatVersion`, `HeaderMACSize`. Before this, a module
  outside cipher-core could not name the `MdstnFile.Recipients` element type
  or the method-2/3 header constants, so building method-2 or method-3
  headers from the SDK was impossible. Behavior is unchanged; the release
  re-cuts binaries only because the Go module surface grew. Consumed by the
  cipher repo's format-0x03 parity suite (spec 068).

## v0.3.1 (2026-11-24)

Two tag re-cuts during publishing fixed release plumbing, one shipped a version-reporting fix.

### Fixed

- `version` subcommand reported "dev" for binaries built by
  `go install github.com/madstone-tech/cipher-core/cmd/mdstn-cipher@vX.Y.Z` (GoReleaser
  binaries were never affected: they are stamped via ldflags). The command now falls back to
  the Go build-info module version when ldflags did not set one; in-module `go build` reports
  the VCS pseudo-version.

### Changed

- The GHCR image moved from `ghcr.io/madstone-tech/mdstn-cipher` (that name is reserved for
  the hosted application) to `ghcr.io/madstone-tech/mdstn-cipher-core`.
- The Homebrew cask's quarantine-removal step now emits Homebrew's `on_macos do …` form;
  the previous cask failed `brew install` with `unknown keyword: :on_macos`.
- README gained an Install section (Homebrew, checksums-verified download, GHCR image,
  `go install`).

## v0.3.0 (2026-11-08)

This release fixes the findings of the external review of 2026-11-04 (F1-F11), its verification
(V1-V3), and six QA verifications (N1-N8, V2-1 to V2-9, Q1-Q8, R-1 to R-11 and W1, S-1 to
S-11, T-1 to T-10, U-1 to U-5). The seventh audit found no new issues. Specs:
`specs/001-review-remediation/` to `specs/006-qa5-remediation/`. Files from `v0.2.x` builds
(`0x01`) cannot be read: there is no v1 reader (final decision).

**Format freeze:** this is the first release tag that ships container format `0x03`. From this
tag on, `0x03` is frozen (`docs/format-spec.md` §Governance): any semantic change needs a new
version byte.

### Security notice: file-password hashes in earlier output

Earlier builds, `v0.2.x` included, printed the SHA-256 of the file password as the "fingerprint" of
a password-encrypted file: in the CLI text and JSON output, in the SDK `EncryptFileResult`, and in
the MCP `encrypt_file` result. Anyone who has that value can test candidate passwords quickly,
without the Argon2id cost. If such output was logged (CI logs, terminal history, MCP transcripts),
treat the password as exposed: encrypt the data again with a new password. This release returns no
fingerprint for password files (Q2).

### Breaking: one container format

- The project has one container format, version byte `0x03`. Files with version `0x01` (written
  by the `v0.2.x` modules) or `0x02` fail with "unsupported version". There is no migration: the
  app was not released. Each reader (for example the web client) must implement `0x03` before
  release.
- The body starts with a 32-byte header MAC, `HMAC-SHA256(HKDF(file_key, "mdstn-cipher/v2/header-mac"), header)`.
  It commits the header to one file key, so a file cannot give different plaintext to different
  recipients (V2-1). The payload key is a separate HKDF subkey of the file key.
- The decoder verifies the header MAC before it decrypts any body byte. A wrong file password
  fails before the body is read.
- Each stream chunk is authenticated with its index and a final-chunk flag. Truncation,
  reordering, repetition, and data after the end fail (F1, F2). The chunk length is bounded before
  allocation (F4). When a stream has more than one frame, the final frame must hold at least one
  byte (V2-4).
- Recipient blocks bind the ephemeral and the recipient public keys into the HKDF salt and carry
  no recipient identifier. A damaged recipient block gives "not a recipient" (exit 3).
- Recipient public keys must be canonical: bit 255 clear, `u < 2^255 − 19`, not low-order. Every
  encryption path checks this before it writes output (V2-2).
- Header base64 values must be strict RFC 4648 standard encoding with no CR or LF (V2-5).
- File passwords use Argon2id (64 MiB, t=3, p=4).
- The password method label is `passphrase-aes256` (was `pbkdf2-aes256`) (N6).
- `original_filename` is informational. It must be a safe base name: not exactly `.` or `..`, at
  most 255 bytes, with no `/`, `\`, `:`, C0 or C1 control character, or invisible character (a
  frozen list of the Unicode 17 Cf, Zl, and Zp characters: bidi controls, zero-width characters,
  the BOM, the soft hyphen, tag characters, line and paragraph separators). Any other value is a
  parse error (Q1, R-6, S-9). Decryptors never use it as a path (R-1).
- Header JSON numbers must be non-negative integers up to 2^53 − 1 (no fraction or exponent).
  `NaN`, lone surrogates, and nesting deeper than 8 levels are parse errors (Q5).
- Pre-release builds `0eb41b9` to `e834a9b` (never tagged) wrote `0x03` without a header MAC. Those
  files fail as a wrong password (method 3) or as tamper (method 2). Decrypt them with the build
  that wrote them, then encrypt them again (Q3).
- The format has no sender authentication. See `docs/format-spec.md` §Limitations (Q8).

### Security: output files and key handling

- All output goes through a staged temporary file with a random name, created exclusively. A failed
  or cancelled operation leaves no file at the output path (F3, F9).
- A supplied key passphrase is always checked. The session cache is used only when the caller gives
  no passphrase (N1). A recovery phrase unlocks only the key it belongs to.
- `DecryptAES` returns an error for a wrong-length nonce instead of a panic.

### CLI

- **Behavior change:** `decrypt` without `-o` writes to the input path without `.mdstn` (or the
  input path plus `.decrypted`), never to a name from the header, and never replaces an existing
  file. `--force` allows replacing that derived path. `-o PATH` replaces a file at `PATH`. No
  option ever replaces the input file. Before, a sender could choose the output path through
  `original_filename` (Q1, R-1, R-2). The CLI shows the sender's name quoted. The MCP
  `decrypt_file` tool never replaces a file.
- `backup` without `-o` writes to `~/.mdstn/backups/` (mode 0700), not to the working directory.
  `.gitignore` ignores `cipher-backup-*.json` (W1).
- The no-replace publish is an atomic rename on Linux (`renameat2`) and macOS (`renamex_np`), with
  a hard-link and then a check-and-rename fallback (R-9).
- A malformed MCP tool call returns an error and the server keeps running (R-5).
- **`encrypt` never replaces `<file>.mdstn`** without `--force` (or `EncryptInput.Overwrite`), and
  never writes over its own input. An output path that is a directory fails before any work, for
  `encrypt` and `decrypt` (S-5, S-7).
- **`backup` never replaces a file**, with or without `-o`. The default name has the date and
  time (`cipher-backup-YYYYMMDD-HHMMSS.json`). `~/.mdstn` and `~/.mdstn/backups` are kept at mode
  0700, and the key database and its SQLite side files at 0600 (S-6).
- Where no atomic no-replace rename or hard link exists (FAT, exFAT), the publish reserves the name
  with an `O_EXCL` placeholder (S-4).
- **No output goes into the folder of a key database** (breaking): not `decrypt` (with `-o`, or a
  derived path such as `<db>-journal.mdstn` → `<db>-journal`), not `encrypt`, not `--force`, not
  `keys export --output`, not `backup -o`, and not the SDK or MCP. SQLite replays a valid
  `<db>-journal` into the database at the next open, so a sender-made journal written there could
  rewrite or empty the key store (T-1). The rule is by folder, not by file name, so case and
  Unicode folding (`\u212a.db-journal` is `k.db-journal` on APFS) cannot get around it (U-3). The
  protected folders are the configured folder, the folder of the resolved file when the database
  path is a symlink (SQLite keeps the journal there, U-1), and any folder that holds a hard link
  to the database (U-4). Subfolders (for example `~/.mdstn/backups/`) are not affected. Database
  paths given as a DSN (`file:…`, `file://localhost/…`, `?_pragma=…`, `%XX` escapes) are decoded
  to the file the driver opens, for this check and the 0600 `chmod` (T-2, U-2). The CLI also
  always protects the default `~/.mdstn/cipher.db` (T-9). With `--db` in a work folder, write
  outputs to another folder. Before, `decrypt -o ~/.mdstn/cipher.db` destroyed every wrapped key.
- An existing default output (`<file>.mdstn` for `encrypt`, the derived path for `decrypt`) is
  reported before any recipient lookup, password prompt, or KDF (T-7).
- SIGINT and SIGTERM abort a command right before its publish step, also for small files, and end
  a password prompt (the terminal mode is restored) (T-6).
- Two default `backup` runs in one second no longer fail: the second gets a `-2` name (T-10).
- `keys export --output` writes through the staged writer (mode 0600, published only when
  complete) and refuses a directory.

### MCP server

- **`export_key` returns the export (id, type, fingerprint, base64 public key) in the tool result
  and writes no file.** The `output` argument is removed. Before, one call could replace any
  file, the key database included (S-1).
- The `create_key` tool is removed: it could not work (it prompted on the protocol stream), and
  a recovery phrase does not belong in an AI transcript (S-3).
- **The `delete_key` tool is removed**: one call per key could destroy every key (T-4). Key
  deletion is the CLI `keys delete`, which asks for confirmation.
- The stdio server follows MCP: it answers `initialize` (protocol versions 2025-06-18 and
  2024-11-05; 2025-03-26 is not offered because it requires batches) and `ping`, never replies to
  a notification, refuses a request whose id is not a string or an integer (`null`, an object, a
  boolean, `1.5`: `-32600`, not run, U-5), stops
  at once on SIGTERM, reports a failed `lookup_key` as `isError` (T-5, T-6), reads one message per line
  (up to 4 MiB), answers a bad line with `-32700`/`-32600` and keeps serving, returns tool results
  as JSON text, and reports tool failures as results with `isError: true` (S-2, S-8).
- `lookup_key` and `import_key` require their arguments.
- A password-encrypted file has no fingerprint, and the CLI prints no fingerprint line for it (Q2).

- `encrypt --recipient-key <base64|path>` encrypts to a raw X25519 public key (F6).
- `encrypt --recipient` no longer asks for a file password (F5). An empty recipient value is a
  usage error (N7).
- New secret inputs: `--password-file` (`encrypt`, `decrypt`) and `--key-passphrase-file`
  (`encrypt`, `decrypt`, `keys create`). The value `-` reads from stdin.
- Exit codes: 0 success, 1 usage or parse error, 2 tampered file, 3 not a recipient, 4 wrong file
  password (F7).
- `keys create --json` returns `recovery_mnemonic` and `recovery_mnemonic_warning` (N2).
- `keys create` without a terminal requires `--yes`, and fails before it creates a key. A failed
  phrase confirmation deletes the new key (N3).
- With `--json`, stdout holds exactly one JSON value. Logs and progress go to stderr (N4).
- Key JSON output uses snake_case fields (`id`, `fingerprint`, `public_key`, `type`, `alias`,
  `is_default`, `created_at`, `expires_at`) and contains no wrapped private key and no salt (N5).
- `decrypt --json` includes `version`.
- Prompts for a key passphrase name the key. Unlocked keys are tried first (V2-6).
- SIGINT and SIGTERM cancel the operation and leave no output file.
- Embedders of `cmd.GetRootCommand()`: the root command sets `SilenceErrors`. Print the error that
  `Execute` returns, and use `cmd.ExitCode(err)` for the exit status.

### SDK and ports — public surface changes

- `Client.EncryptStream(ctx, src, dst, EncryptStreamInput) error` and
  `Client.DecryptStream(ctx, src, dst, DecryptStreamInput) (*DecryptStreamResult, error)` replace
  the stubs that always failed (F10). On a `DecryptStream` error, discard `dst`.
- `EncryptStream` with no intent requires an existing default key.
- Each call keeps its passphrase input to itself. Concurrent calls on one `Client` do not share
  secret state (N8). `Lock` and `LockAll` end the session cache for every caller.
- New: `cipher.InMemory` for `Config.DBPath` (no key database on disk).
- New error classes: `cipher.ErrHeaderAuthFailed`, `ErrNotARecipient`, `ErrWrongPassword`,
  `ErrInvalidRecipientKey`.
- `DecryptFileResult` and `DecryptStreamResult` have a `Version` field (V2-7).
- `DecryptInput.Overwrite` allows the default output path to replace an existing file (Q1).
- `EncryptStreamInput.OriginalFilename` must be a safe base name, else `ErrInvalidInput` (Q1).
- `EncryptFileResult.Fingerprint` is empty for password files, as documented (Q2).
- `CreateKey` starts a session for the new key; the godoc now says so (Q8). Every session entry
  uses `Config.SessionTTL` (default 15 minutes); nothing hard-codes 30 minutes any more (R-11).
- An existing default output path gives an error that matches `cipher.ErrAlreadyExists` and
  `fs.ErrExist` (R-10), for `Decrypt` and `Encrypt`.
- New: `EncryptInput.Overwrite`, `DecryptFileResult.OriginalFilename` (S-5, S-10). The SDK
  refuses any output path in the folder of its own key database (`Config.DBPath`).
- `New` returns an error when it needs the default database but the home directory is unknown or
  `~/.mdstn` cannot be created; it no longer falls back to `./cipher.db` (T-3).
- `keys export --format pem` labels the block `MDSTN WRAPPED X25519 PRIVATE KEY` (it holds the
  wrapped key, not a raw key) (T-8).
- A KEK that a decryption unlocks is cached, and key usage is counted, only after the file
  authenticates and the output is published (R-7, R-8).
- The default SDK logger writes to stderr.
- `cipherports.CryptoEngine`: new `HeaderMAC`, `VerifyHeaderMAC`, `DerivePayloadKey`,
  `ValidatePublicKey`, `DeriveFileKeyArgon2id`. `DeriveKey` (PBKDF2 file keys) is removed.
- `cipherports.FileEncoder`: new `DecodeHeader(r io.Reader)`. `EncodeHeader` writes `0x03` only.

### Spec, vectors, tooling

- `docs/format-spec.md` describes the one format, with runnable Python pseudocode, a normative
  tamper contract, and error classes (F8, V2-8, V2-9).
- New vector set: every method and framing, stream lengths 0, 1, 65535, 65536, 65537, and 131072
  bytes, and negative fixtures with their expected failure class (V2-3).
- Every vector and negative fixture also runs through the production `DecryptFile` path (Q7).
  New negative fixtures: `bad-filename` and `nan-in-header`.
- A key's usage counter changes only after the header MAC and the body authenticate (Q6).
- errcheck `check-blank` reports each explicit error discard. Each `nolint:errcheck` carries a
  reason (F11, N8).
- The CI secret scan passes. The external SDK proof builds against the local tree (V3).
