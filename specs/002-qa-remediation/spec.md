# Feature Specification: QA Remediation and Single Container Format

**Feature Branch**: `002-qa-remediation`

**Created**: 2026-11-04

**Status**: Clarified

**Input**: User description: "Address the QA verification findings
(`cipher-core-review-2026-11-04/cipher-core-verification.md`, N1-N8 and V2-1 to V2-9). The app is
not released: drop the old v1 and v2 standards and make this version the one correct format."

## Source Findings

| ID | Finding | Covered by |
|---|---|---|
| N1 | After one unlock, a wrong or empty key passphrase is accepted for the session lifetime. | US2 |
| N2 | `keys create --json` does not give the recovery phrase. | US3 |
| N3 | `keys create` stores the key when the phrase confirmation fails. | US3 |
| N4 | `--json` stdout has log and progress lines before the JSON. | US3 |
| N5 | `keys --json` has Go field names and wrapped key material and salts. | US3 |
| N6 | Password files are labeled `pbkdf2-aes256`. Some SDK comments are stale. | US4 |
| N7 | An empty `--recipient` value falls back to a password prompt. | US3 |
| N8 | Data race on shared `Client` prompter state. Five `nolint:errcheck` lines have no reason. | US2, US5 |
| V2-1 | No key commitment: each recipient can get different plaintext from one file. | US1 |
| V2-2 | A non-canonical recipient public key gives a file that its owner cannot decrypt. | US1 |
| V2-3 | The vectors do not test the final-chunk flag at its edges. | US1 |
| V2-4 | A full non-final frame followed by an empty final frame is accepted. | US1 |
| V2-5 | The Go decoder accepts CR/LF inside base64 header values. | US1 |
| V2-6 | Recipient trial prompts with the same text for each key. | US2 |
| V2-7 | Results do not give the container version. | US4 |
| V2-8 | A code comment says the header is not covered by the AEAD. | US5 |
| V2-9 | The spec and the contract disagree with the code on two details. | US5 |

## Clarifications

### Session 2026-11-04

- Q: Where do the format fixes go? → A: Into the one format now, before the first release tag.
  The app is not released. Drop the old v1 (`0x01`) format and the retired `0x02`. There is one
  correct format.
- Q: How do we proceed? → A: Spec-kit feature 002, implement all findings.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One correct, committing, canonical format (Priority: P1)

An operator encrypts backups to one or more recipients. Each recipient must get the same plaintext
or an error. A recipient key that the owner cannot use must fail at encryption time. Two
implementations of the spec must accept and reject the same files.

**Why this priority**: V2-1 and V2-2 break the core promise. The format is not released, so this is
the last cheap moment to fix it.

**Independent Test**: build the V2-1 two-CEK file, the V2-2 bit-255 key, the V2-4 empty final frame,
and the V2-5 CR/LF header. Each fails. A `0x01` file fails with "unsupported version".

**Acceptance Scenarios**:

1. **Given** a file whose recipient blocks wrap different content keys, **When** any recipient
   decrypts it, **Then** the decryption fails with the tamper class and writes no plaintext.
2. **Given** a recipient public key with bit 255 set or with `u ≥ 2^255 − 19`, **When** the user
   encrypts to it by any path (raw key, local key, CKD lookup, SDK), **Then** the encryption fails
   with a usage error before any output.
3. **Given** a stream that ends with a full frame and then an empty final frame, **When** it is
   decrypted, **Then** it fails with the tamper class.
4. **Given** a header with CR, LF, or non-canonical padding in a base64 value, **When** it is
   decoded, **Then** it fails with a parse error.
5. **Given** a file with version byte `0x01` or `0x02`, **When** it is decoded, **Then** it fails
   with "unsupported version".
6. **Given** a password file and a wrong password, **When** it is decrypted, **Then** it fails with
   the wrong-password class before it reads the body. **Given** the right password and a damaged
   body, **Then** it fails with the tamper class.

---

### User Story 2 - A supplied passphrase is always checked (Priority: P1)

A service shares one SDK client between callers. A caller who gives a wrong passphrase must fail,
even if another caller unlocked the same key earlier.

**Why this priority**: N1 is an authorization failure in any multi-caller host (MCP server, web
backend).

**Independent Test**: unlock with the right passphrase, then decrypt with a wrong one on the same
client. It fails. Two goroutines on one client pass the race detector.

**Acceptance Scenarios**:

1. **Given** an unlocked key, **When** a caller gives a wrong passphrase, **Then** the call fails
   and the cached unlock is not used.
2. **Given** an unlocked key, **When** a caller gives an empty passphrase, **Then** the cached
   unlock is used (documented).
3. **Given** a client, **When** the caller calls `LockAll()` (or `Lock(keyID)`), **Then** each later call needs a
   passphrase.
4. **Given** two goroutines that call `DecryptStream` on one client, **When** the race detector
   runs, **Then** it reports no race.
5. **Given** several locked keys, **When** the decryptor tries them, **Then** each prompt names the
   key, and unlocked keys are tried first.

---

### User Story 3 - Scriptable key management and JSON output (Priority: P2)

A script creates a key, stores its recovery phrase, and parses the JSON output of each command.

**Why this priority**: the unattended inputs from feature 001 invite scripts. Today a script can
make a key with no backup, or two keys after a retry.

**Independent Test**: `json.Unmarshal` the stdout of each `--json` command. `keys create --json`
gives 24 words. A failed confirmation leaves no key.

**Acceptance Scenarios**:

1. **Given** `keys create --json`, **When** it succeeds, **Then** stdout is one JSON object with
   `recovery_mnemonic` (24 words) and `recovery_mnemonic_warning`.
2. **Given** `keys create` without a TTY and without `--yes`, **When** it runs, **Then** it fails
   with a usage error that names `--yes`, and the key store is unchanged.
3. **Given** any `--json` command, **When** it runs, **Then** stdout is exactly one JSON value.
   Logs and progress go to stderr.
4. **Given** `keys list --json` or `keys create --json`, **When** it runs, **Then** the field names
   are snake_case and the output has no wrapped private key and no salt.
5. **Given** `encrypt --recipient ""`, **When** it runs, **Then** it fails with a usage error.

---

### User Story 4 - Honest labels and results (Priority: P3)

A caller reads the method and the container version of a file from the CLI or SDK result.

**Independent Test**: encrypt with a password and read the method label and the version from the
JSON output and the SDK result.

**Acceptance Scenarios**:

1. **Given** a password file, **When** the CLI or SDK reports the method, **Then** the label names
   no KDF that the file does not use.
2. **Given** a decryption, **When** it succeeds, **Then** the result has the container version.

---

### User Story 5 - Accurate spec, comments, and lint (Priority: P3)

A reimplementer follows the spec. A maintainer relies on the lint rules.

**Independent Test**: the Python pseudocode decrypts every vector and rejects every negative
fixture. Lint reports no `nolint:errcheck` without a reason.

**Acceptance Scenarios**:

1. **Given** the spec, **When** a reader follows it, **Then** it describes one container format,
   the header MAC, canonical keys, strict base64, and the canonical final frame.
2. **Given** the vectors, **When** a decoder runs them, **Then** they include streams of 0, 65536,
   and 131072 bytes, and negative fixtures with their failure class.
3. **Given** the code, **When** a maintainer reads the header-parsing comment, **Then** it is
   correct.

### Edge Cases

- A recipient block that unwraps but fails the header MAC: tamper class, not "not a recipient".
- A password file whose header is changed: the MAC fails, so the class is wrong password. This is
  documented.
- Empty plaintext: one final frame of 0 bytes is the only valid encoding.
- An all-zero or low-order public key, a 31-byte key, a key with bit 255 set: all rejected.
- A CKD directory that returns a non-canonical key: encryption fails before output.

## Requirements *(mandatory)*

### Functional Requirements

**Format (US1)**

- **FR-001**: The project MUST have one container format, version byte `0x03`. Decoders MUST reject
  `0x01`, `0x02`, and unknown versions with "unsupported version". All code, tests, vectors, and
  fixtures for `0x01` MUST be removed.
- **FR-002**: The body MUST start with a 32-byte header MAC:
  `HMAC-SHA256(HKDF-SHA256(ikm=file_key, info="mdstn-cipher/v2/header-mac"), headerAAD)`.
  The payload key MUST be `HKDF-SHA256(ikm=file_key, info="mdstn-cipher/v2/payload")`.
  (The label prefix `v2` names the format, as the existing wrap labels do. The version byte is `0x03`.)
  The decoder MUST verify the MAC in constant time before it decrypts any body byte.
- **FR-003**: For method 2, a block that unwraps but fails the MAC MUST give the tamper class.
  For method 3, a MAC failure MUST give the wrong-password class. After the MAC passes, every body
  failure MUST give the tamper class.
- **FR-004**: Recipient public keys MUST be canonical: 32 bytes, bit 255 clear, `u < 2^255 − 19`,
  and not low-order. Every encryption path MUST validate them before any output.
- **FR-005**: When the stream has more than one frame, the final frame MUST hold at least 1
  plaintext byte.
- **FR-006**: Base64 header values MUST be strict RFC 4648 standard encoding with padding, and
  MUST NOT contain CR or LF.
- **FR-007**: The vectors MUST include stream lengths 0, 1, 65535, 65536, 65537, and 131072 bytes
  for at least one method, and negative fixtures (truncation plus terminator, frame after the final
  frame, frame 0 removed, empty final frame, two-CEK file, CR/LF header, version `0x01`) with their
  failure class.

**Key handling (US2)**

- **FR-008**: When a caller gives a key passphrase, the decryptor MUST unwrap the key with it and
  MUST fail if it is wrong. A cached unlock MUST be used only when the passphrase is empty.
- **FR-009**: The SDK MUST keep passphrase input per call, not in shared client state.
  `Client.LockAll()` (existing API) MUST clear all cached unlocks.
- **FR-010**: Recipient trial MUST try unlocked keys first, and each prompt MUST name the key.

**CLI (US3)**

- **FR-011**: `keys create --json` MUST output `recovery_mnemonic` and `recovery_mnemonic_warning`.
- **FR-012**: `keys create` without `--yes` and without a TTY MUST fail before it creates a key.
- **FR-013**: In `--json` mode, stdout MUST hold exactly one JSON value. Logs and progress MUST go
  to stderr. The SDK default logger MUST write to stderr.
- **FR-014**: Key JSON output MUST use snake_case names and MUST NOT contain wrapped private keys or
  salts.
- **FR-015**: An empty recipient value MUST be a usage error.

**Labels, results, tooling (US4, US5)**

- **FR-016**: The password method label MUST be `passphrase-aes256`. Results MUST include the
  container version.
- **FR-017**: Comments and the spec MUST match the code (V2-8, V2-9, N6 comments).
- **FR-018**: Each `nolint:errcheck` MUST carry a reason.

### Key Entities

- **File key**: 32 bytes. Random CEK (method 2), Argon2id output (method 3), policy key (method 5).
- **Header MAC**: 32 bytes at the start of the body. Commits the header to the file key.
- **Key output DTO**: `id`, `fingerprint`, `public_key`, `type`, `alias`, `is_default`,
  `created_at`, `expires_at`.

## Success Criteria *(mandatory)*

- **SC-001**: The two-CEK file, bit-255 key, empty final frame, CR/LF header, and `0x01` file each
  fail in 100% of runs with the documented class.
- **SC-002**: After an unlock, a wrong passphrase fails in 100% of runs.
- **SC-003**: `json.Unmarshal` succeeds on the stdout of 100% of `--json` commands.
- **SC-004**: `go test -race` passes for two goroutines on one client.
- **SC-005**: The spec pseudocode decrypts 100% of the vectors and rejects 100% of the negative
  fixtures.
- **SC-006**: `task ci` passes.

## Assumptions

- No `.mdstn` file produced by this project needs to stay readable: the app is not released
  (user decision). The web client must adopt this format before release.
- The version byte stays `0x03` so that files from the public `v0.2.x` module versions get a clear
  "unsupported version" error instead of a wrong parse.
- The key-backup bundle and the key-at-rest wrapping are not container formats. They do not change.
- The header MAC follows the age header MAC design. No new dependency.
