# Feature Specification: QA Verification 3 Remediation

**Feature Branch**: `004-qa3-remediation`

**Created**: 2026-11-06

**Status**: Clarified

**Input**: User description: "Address the findings of
`cipher-core-review-2026-11-04/cipher-core-verification-3.md` (R-1 to R-11, W1)."

## Clarifications

### Session 2026-11-06

- Q: Without `-o`, which name does decrypt use (R-1, R-2)? → A: The input name only. The header's
  `original_filename` is shown, never used as a path.
- Q: The key backup in the repository folder (W1)? → A: Move it to `~/.mdstn/backups/`, ignore
  `cipher-backup-*.json`, and make `backup` write there by default.
- Q: Proceed? → A: Spec-kit feature 004, implement all.

## Requirements

- **FR-001 (R-1, R-2)**: Without an explicit output path, the output path MUST be the input path
  without `.mdstn`, or the input path plus `.decrypted` when it has no `.mdstn` suffix. A decryptor
  MUST NOT use `original_filename` as any part of a path. It MAY show it, quoted.
- **FR-002 (R-2)**: A decryptor MUST refuse an output path that is the same file as the input, with
  or without `--force`/`Overwrite`, and with an explicit `-o`.
- **FR-003 (R-4)**: The staged temporary file name MUST have a fixed length that does not depend on
  the output name.
- **FR-004 (R-6)**: A safe base name MUST also exclude C1 controls (U+0080–U+009F) and bidi
  controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069). Go and the spec Python agree.
  A negative fixture pins it.
- **FR-005 (R-3)**: The spec Python MUST reject a number with a sign, `-0` included.
- **FR-006 (R-5)**: A malformed MCP tool call MUST return a JSON-RPC error, and MUST NOT stop the
  server. Each tool call recovers from a panic.
- **FR-007 (R-7, R-8)**: A key-encryption key unlocked during a decryption MUST be cached, and key
  usage MUST be recorded, only after the file authenticates and (for a file output) the output is
  committed.
- **FR-008 (R-9)**: The no-replace publication MUST use an atomic no-replace rename where the OS
  has one (Linux `renameat2(RENAME_NOREPLACE)`, macOS `renamex_np(RENAME_EXCL)`), then a hard link,
  then check-then-rename. The "exists" error MUST match `cipher.ErrAlreadyExists` and
  `fs.ErrExist`. The CLI error names `-o` and `--force`.
- **FR-009 (R-10)**: The CHANGELOG, the stream godoc, and the `-o` help text MUST match the
  behavior.
- **FR-010 (R-11)**: Every session-cache entry MUST use the configured session TTL
  (`Config.SessionTTL`, default `DefaultSessionTTL`). No code path hard-codes a TTL.
- **FR-011 (W1)**: `mdstn-cipher backup` without `-o` MUST write to `~/.mdstn/backups/`
  (directory mode 0700, file mode 0600). `.gitignore` MUST ignore `cipher-backup-*.json`.

## Success Criteria

- **SC-001**: No header value changes where decrypt writes. `--force` never replaces the input.
- **SC-002**: A 255-byte name decrypts to the default path.
- **SC-003**: A malformed MCP call gets an error answer, and the next call is answered.
- **SC-004**: Go and the spec Python agree on every negative fixture and on the R-3/R-6 cases.
- **SC-005**: `task ci` passes.

## Assumptions

- `original_filename` stays in the header (informational). The decoder still rejects unsafe values.
- `golang.org/x/sys` becomes a direct dependency for the no-replace rename. It is already an
  indirect dependency (`go.mod`), from the same project as `golang.org/x/crypto`.
