# Feature Specification: QA Verification 2 Remediation

**Feature Branch**: `003-qa2-remediation`

**Created**: 2026-11-05

**Status**: Clarified

**Input**: User description: "Address the findings of
`cipher-core-review-2026-11-04/cipher-core-verification-2.md` (Q1-Q8)."

## Clarifications

### Session 2026-11-05

- Q: What do we do with v1 files from the `v0.2.x` module tags (Q4)? → A: Keep them dropped. No v1
  reader, in this module or in a separate tool.
- Q: How do we proceed? → A: Spec-kit feature 003, implement all.

## Source Findings

| ID | Severity | Finding | Covered by |
|---|---|---|---|
| Q1 | High | The sender chooses the output path through `original_filename`. | US1 |
| Q2 | High | The password-file "fingerprint" is SHA-256 of the password. | US2 |
| Q3 | Low | Pre-release `0x03` files (no header MAC) give a misleading error. Not documented. | US4 |
| Q4 | Decision | v1 files cannot be read. | Clarification: keep dropped. US4 documents it. |
| Q5 | Info | The spec Python header parser accepts JSON that Go rejects. | US3 |
| Q6 | Info | The key usage counter changes before the header MAC check. | US3 |
| Q7 | Info | The normative tests do not run the production decrypt code. | US3 |
| Q8 | Info | No sender authentication is not documented. `CreateKey` starts a session. | US4 |

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A received file cannot choose where its plaintext goes (Priority: P1)

A user or an AI agent decrypts a file from someone else without an explicit output path.

**Independent Test**: make files whose `original_filename` is `../victim/x`, an absolute path, and
a name of an existing file. Decrypt each without `-o` from another directory.

**Acceptance Scenarios**:

1. **Given** a header whose `original_filename` is not a safe base name, **When** it is decoded,
   **Then** it fails with a parse error (exit 1) and no file is written.
2. **Given** no output path, **When** the file decrypts, **Then** the output goes into the directory
   of the input file, not the working directory.
3. **Given** no output path and an existing file at the default output path, **When** the file
   decrypts, **Then** it fails with exit 1 and the existing file is unchanged. With `--force` (CLI)
   or `Overwrite` (SDK), it replaces the file.
4. **Given** an SDK caller that passes an `OriginalFilename` that is not a safe base name,
   **When** it encrypts, **Then** it fails with a usage error before any output.
5. **Given** a local input file whose base name is not a safe base name, **When** it is encrypted,
   **Then** the header stores no `original_filename`.

### User Story 2 - No output reveals a file password (Priority: P1)

**Independent Test**: encrypt with a known password through the CLI (text and JSON), the SDK, and
MCP. No output contains `sha256(password)` or any value derived from the password.

**Acceptance Scenarios**:

1. **Given** a file password, **When** a file is encrypted, **Then** the result fingerprint is empty
   on every surface, and the CLI text output prints no fingerprint line.

### User Story 3 - Conforming readers agree, and the key store changes only on success (Priority: P3)

**Acceptance Scenarios**:

1. **Given** a header with a fractional, exponent, negative, or larger than 2^53 − 1 number, a lone
   UTF-16 surrogate, `NaN` or `Infinity`, or nesting deeper than 8 levels, **When** Go or the spec
   Python decodes it, **Then** both fail with a parse error.
2. **Given** a file that a local key opens but whose header MAC or body fails, **When** it is
   decrypted, **Then** no key usage counter changes.
3. **Given** the vectors and negative fixtures, **When** the tests run, **Then** each one also runs
   through the production `DecryptFile.DecryptStream` with the expected class.

### User Story 4 - Documentation matches the limits (Priority: P3)

**Acceptance Scenarios**:

1. **Given** the spec and the CHANGELOG, **When** a reader checks them, **Then** they say that
   pre-release builds `0eb41b9..e834a9b` wrote `0x03` without a header MAC, and that v1 files
   cannot be read.
2. **Given** §Limitations, **When** a reader checks it, **Then** it says that the format has no
   sender authentication.
3. **Given** the `CreateKey` godoc, **When** a reader checks it, **Then** it says that `CreateKey`
   starts a session and names `Lock`/`LockAll`.

## Requirements *(mandatory)*

- **FR-001**: A safe base name is 1 to 255 bytes of valid UTF-8, is not `.` or `..`, and contains
  no `/`, `\`, `:`, and no control character (U+0000-U+001F, U+007F). An empty
  `original_filename` means "no name".
- **FR-002**: The decoder MUST reject an `original_filename` that is neither empty nor a safe base
  name (parse error). The encoder MUST NOT write one.
- **FR-003**: Without an explicit output path, the output path MUST be `dir(input) / name`, where
  `name` is `original_filename`, else the input base name without `.mdstn`, else `decrypted`.
- **FR-004**: Without an explicit output path, publication MUST fail if the path exists, unless the
  caller asks to overwrite. The check and the publication MUST be one atomic step where the file
  system supports hard links.
- **FR-005**: A password-file encryption MUST return an empty fingerprint on every surface.
- **FR-006**: Header numbers MUST be integers in [0, 2^53 − 1] without fraction or exponent. Strings
  MUST NOT contain lone surrogates. Nesting MUST NOT exceed 8 levels. Go and the spec Python MUST
  enforce the same rules.
- **FR-007**: Key usage MUST be recorded only after the header MAC and the body authenticate.
- **FR-008**: Every vector and negative fixture MUST also run through `DecryptFile.DecryptStream`.
- **FR-009**: Negative fixtures MUST include a `../x` filename and a `NaN` header.

## Success Criteria *(mandatory)*

- **SC-001**: 0 of the Q1 attack files write outside the input directory or replace a file.
- **SC-002**: 0 outputs contain `sha256(password)`.
- **SC-003**: Go and the spec Python agree on 100% of the negative fixtures.
- **SC-004**: `task ci` passes.

## Assumptions

- Existing `0x03` vectors keep their bytes: their names are safe base names and their numbers are
  small integers. Only new negative fixtures are added (append-only generator).
- An explicit `-o` / `OutputPath` keeps today's behavior: it replaces an existing file.
- MCP decrypt never overwrites: it passes no output path and no overwrite flag.
