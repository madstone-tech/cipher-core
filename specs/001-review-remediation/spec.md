# Feature Specification: Review Remediation (2026-11-04)

> **Superseded in part by `specs/002-qa-remediation/`** (2026-11-05). The app was not released, so
> feature 002 removed the `0x01` format (no v1 read path, no v1 vectors) and changed `0x03`
> before its first tag: header MAC, canonical keys, strict base64, canonical final frame. Read
> the v1 and format-v2 statements below as history.

**Feature Branch**: `001-review-remediation`

**Created**: 2026-11-04

**Status**: Clarified

**Input**: User description: "Address all the issues in the external review
`cipher-core-review-2026-11-04/cipher-core-review.md` (findings F1-F11 and the attached patch),
plus the issues found when the review was verified."

## Source Findings

| ID | Finding | Covered by |
|---|---|---|
| F1 | Stream chunks can be reordered, repeated, or removed, and decryption succeeds. | US1 |
| F2 | Stream truncation at a chunk boundary is not detected. | US1, US4, US8 |
| F3 | A failed stream decryption or encryption publishes a partial output file. | US1 |
| F4 | The chunk length field has no upper limit. A 28-byte file causes a 4 GiB allocation. | US1 |
| F5 | `encrypt --recipient` asks for a file password and fails without a terminal. | US2 |
| F6 | The CLI has no public-key-only recipient path. The SDK always opens a database. | US2 |
| F7 | All CLI errors exit with code 1. The spec defines codes 0-4. | US3 |
| V1 | A wrong file password on a file of 1 MiB or more is reported as tampering. | US3 |
| F8 | The format spec pseudocode and the CLI help text are wrong in 7 places. | US4 |
| V2 | No committed test vector covers the chunked stream. | US4 |
| F9 | Temporary output names are predictable and opened without exclusive create. | US5 |
| F10 | The frozen SDK exports two stream methods that always fail. | US6 |
| F11 | 45 silent error discards. The lint configuration does not flag explicit discards. | US7 |
| V3 | The CI secret scan fails on the committed tree (`tests/external-sdk/main.go:19`). | US7 |

V1-V3 come from the verification of the review, not from the review itself.

## Clarifications

### Session 2026-11-04

- Q: How do we handle stream truncation (F2)? → A: Ship a new container version with an
  authenticated end-of-stream and all review design notes: public keys in the KDF, no recipient
  hint, and the memory-hard KDF for file passwords (FR-006, FR-022 to FR-027).
- Q: Which CLI surface for a raw recipient public key (F6)? → A: A `--recipient-key` flag on
  `encrypt` (FR-010).
- Q: What do we do with the SDK stream stubs (F10)? → A: Implement them (FR-018).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Tampered stream files fail and leave no output (Priority: P1)

An operator stores encrypted backups where other parties can write. When the operator decrypts a
backup that someone changed, the tool must refuse it and must not leave any plaintext on disk.

**Why this priority**: today an attacker can change the order or the number of chunks in any file
of 1 MiB or more, and the decryption reports success. This breaks the main promise of the product.

**Independent Test**: encrypt a 1.25 MiB file. Make each frame-level change from the review
(swap, repeat, remove, truncate, bit flip, forged length). Decrypt each result to an output path.
Check the exit status and check that no file exists at the output path.

**Acceptance Scenarios**:

1. **Given** a stream file with two chunks swapped, **When** the user decrypts it, **Then** the
   decryption fails with the tamper error class and no output file exists.
2. **Given** a stream file with one chunk repeated in place of others, **When** the user decrypts
   it, **Then** the decryption fails with the tamper error class and no output file exists.
3. **Given** a stream file with a middle chunk removed, **When** the user decrypts it, **Then**
   the decryption fails with the tamper error class and no output file exists.
4. **Given** a stream file with one bit changed in chunk 10 of 20, **When** the user decrypts it,
   **Then** the decryption fails and no output file exists (today 640 KiB of plaintext remain).
5. **Given** a 28-byte file with a chunk length of `0xFFFFFFF0`, **When** the user decrypts it,
   **Then** the decryption fails before it reserves memory for the chunk.
6. **Given** an encryption that fails after it starts to write, **When** the error occurs,
   **Then** no partial `.mdstn` file exists at the output path.
7. **Given** a new-version stream file truncated at a chunk boundary with a terminator added,
   **When** the user decrypts it, **Then** the decryption fails with the tamper error class and no
   output file exists. For a v1 file, the documented v1 limitation applies (FR-015).
8. **Given** a stream file that was not changed, **When** the user decrypts it, **Then** the output
   is byte-identical to the original. Files written by earlier releases still decrypt.

---

### User Story 2 - Unattended encryption to a public key (Priority: P1)

A Kubernetes CronJob encrypts a daily snapshot to the operator's public key. The Job has no
terminal, no private key, and no persistent database.

**Why this priority**: this is the use case in the review. Today the CLI cannot do it at all.

**Independent Test**: in a fresh, empty environment with stdin from `/dev/null`, encrypt a file to
a public key that is given on the command line. Then decrypt the result on a second machine that
has the private key.

**Acceptance Scenarios**:

1. **Given** a recipient key in the local key store and no terminal, **When** the user runs
   `encrypt --recipient <id>`, **Then** the encryption succeeds without a password prompt.
2. **Given** only a recipient public key and no local private key, **When** the user encrypts to
   that key with the public-key-only path from FR-010, **Then** the encryption succeeds and the
   host stores no private key.
3. **Given** an SDK consumer with only a recipient public key, **When** it encrypts, **Then** the
   operation succeeds without a key database on disk.
4. **Given** a command that needs a passphrase (`keys create`, `decrypt` of a password file) and no
   terminal, **When** the passphrase comes from a non-interactive input, **Then** the command
   succeeds. The passphrase does not appear in the process argument list.
5. **Given** an invalid public key (wrong length, bad encoding, low-order point), **When** the user
   encrypts to it, **Then** the command fails with a usage error before it writes output.

---

### User Story 3 - Scripts can tell failures apart (Priority: P2)

A backup script decides what to do from the exit code: alert on tampering, try another key on
"not a recipient", or ask again for a password.

**Why this priority**: the spec makes the exit codes normative for the reference decryptor, and
scripts cannot parse localized error text.

**Independent Test**: run one CLI case for each exit code and compare the observed code with the
table in `docs/format-spec.md` §Governance item 5.

**Acceptance Scenarios**:

1. **Given** a tampered file, **When** the user decrypts it, **Then** the exit code is 2.
2. **Given** a file for a different key, **When** the user decrypts it, **Then** the exit code is 3.
3. **Given** a password file of any size and a wrong password, **When** the user decrypts it,
   **Then** the exit code and the message are the same for the in-memory and the stream framing.
4. **Given** a usage or parse error, **When** the command fails, **Then** the exit code is 1.
5. **Given** success, **When** the command ends, **Then** the exit code is 0.

---

### User Story 4 - Implementers can follow the format spec (Priority: P2)

A developer writes a second decryptor from `docs/format-spec.md` alone and checks it against the
committed test vectors.

**Why this priority**: the spec calls itself reimplementation-grade. Today a reader who follows the
pseudocode gets wrong results, and no vector covers the framing that all large files use.

**Independent Test**: a reviewer follows each pseudocode block against the code and the vectors.
Each block gives the same result as the reference implementation.

**Acceptance Scenarios**:

1. **Given** the multi-recipient and bundle pseudocode, **When** a reader follows it, **Then** it
   uses the separate `nonce` field, the full `wrapped_cek`, and the normative wrap AAD.
2. **Given** the spec, **When** a reader looks for stream decryption, **Then** a pseudocode block
   shows the chunk loop, the derived-nonce check, and the length bound.
3. **Given** the tamper contract, **When** a reader checks it, **Then** it lists the frame-level
   mutations (swap, repeat, remove, forged length) and their failure class.
4. **Given** the committed vectors, **When** a conforming implementation runs them, **Then** at
   least one vector covers a chunked stream.
5. **Given** §Limitations, **When** a reader checks it, **Then** it states that v1 files cannot
   detect truncation at a chunk boundary, and that new files use the new container version.
6. **Given** `encrypt --help`, **When** a user reads it, **Then** the text matches the behavior
   and the examples are numbered in sequence.

---

### User Story 5 - Safe temporary files (Priority: P3)

A user decrypts into a directory that other local users can write.

**Why this priority**: the risk needs a shared, writable directory. The fix is small.

**Independent Test**: create a symlink at the old predictable temporary path, then encrypt and
decrypt into that directory. The symlink target stays unchanged.

**Acceptance Scenarios**:

1. **Given** an attacker-placed symlink at any predictable path near the output, **When** the user
   writes output, **Then** the tool does not follow the symlink.
2. **Given** a stale temporary file from a crashed encryption or decryption, **When** the cleanup
   runs, **Then** it removes stale files of both kinds.

---

### User Story 6 - Honest SDK surface (Priority: P3)

An SDK consumer reads the API documentation and calls only methods that work.

**Why this priority**: two exported methods always fail. The constitution forbids this.

**Independent Test**: list the exported methods of `pkg/cipher` and call each stream method with a
real input.

**Acceptance Scenarios**:

1. **Given** the SDK, **When** a consumer calls a stream method, **Then** the behavior follows
   FR-018.

---

### User Story 7 - Error discipline and CI stay green (Priority: P3)

A maintainer relies on the lint and the CI to enforce the project rules.

**Why this priority**: the rule "handle every error" has no automatic check, and the CI secret scan
currently fails on the committed tree.

**Independent Test**: run the full CI task set on a clean checkout. Add a new silent discard and
check that the lint reports it.

**Acceptance Scenarios**:

1. **Given** a new `_ = f()` that discards an error outside the allow list, **When** lint runs,
   **Then** lint reports it.
2. **Given** the committed tree, **When** CI runs, **Then** every job passes, the secret scan too.

### User Story 8 - New files resist truncation, key substitution, and recipient linking (Priority: P2)

An operator encrypts new backups. A truncated file must fail. A party that knows a candidate public
key must not be able to tell whether a file is for that key. A password file must resist GPU attacks
as well as a wrapped private key does.

**Why this priority**: truncation is a High finding (F2), and v1 cannot fix it. The other three
design notes from the review change the same container, so one format change covers all four.

**Independent Test**: encrypt new files with each method. Check the version byte. Truncate a stream
at each chunk boundary and decrypt. Inspect the header for recipient identifiers. Decrypt every
committed v1 vector and every new-version vector.

**Acceptance Scenarios**:

1. **Given** any new encryption, **When** the file is written, **Then** it uses the new container
   version.
2. **Given** a new-version stream truncated at any chunk boundary, with or without a terminator,
   **When** the user decrypts it, **Then** it fails with the tamper error class.
3. **Given** a new-version stream with data after the final chunk, **When** the user decrypts it,
   **Then** it fails with the tamper error class.
4. **Given** a new-version recipient file and a candidate public key, **When** a party without the
   private key inspects the header, **Then** no field depends on the recipient public key.
5. **Given** a new-version recipient file and several local private keys, **When** the user
   decrypts, **Then** the tool finds the correct key without a recipient hint.
6. **Given** a new-version password file, **When** the key is derived, **Then** the KDF is the same
   memory-hard KDF that protects private keys at rest.
7. **Given** a v1 file from any earlier release, **When** the user decrypts it, **Then** it still
   decrypts, with the v1 rules.

---

### Edge Cases

- A plaintext length that is an exact multiple of 64 KiB, including zero: the last chunk is full
  size or no chunk exists. Round trips and tamper checks must work for these lengths.
- A chunk length field of 0 before any chunk: empty plaintext, valid only as written by the encoder.
- A chunk length field between the maximum and `0xFFFFFFFF`: rejected before allocation.
- An output path on a different filesystem from its temporary file: publication must stay atomic,
  so the temporary file must be in the same directory as the output.
- A failure during the cleanup of a temporary file: the original error stays the reported error,
  and the cleanup failure is added to it.
- A file written by a third-party encoder with non-derived chunk nonces: it is rejected, because
  spec §5 already requires derived nonces.
- Cancellation (Ctrl-C or context cancel) during a stream: no output file remains.

## Requirements *(mandatory)*

### Functional Requirements

**Stream integrity (US1)**

- **FR-001**: The stream decryptor MUST derive the expected nonce of each chunk from the base nonce
  and the chunk index, and MUST reject a chunk whose on-wire nonce is different.
- **FR-002**: The stream decryptor MUST reject a chunk length greater than one full chunk plus the
  authentication tag before it reserves memory for the chunk.
- **FR-003**: A failed or cancelled stream decryption MUST NOT leave a file at the output path.
- **FR-004**: A failed or cancelled stream encryption MUST NOT leave a file at the output path.
- **FR-005**: The output-stream port MUST make publication an explicit success step, so that no
  implementation of the port can publish on a failure path. This port is internal (it is not
  re-exported by `pkg/cipherports`), so the change does not alter the public surface.
- **FR-006**: New files MUST use a new container version. In that version, the decryptor MUST know
  which chunk is the final chunk from authenticated data. Truncation at any chunk boundary, a missing
  final chunk, and data after the final chunk MUST each fail with the tamper error class.
- **FR-007**: Files written by all earlier releases of the v1 encoder MUST still decrypt with the v1
  rules. The v1 rules MUST NOT change (Principle III), except for the stricter checks in FR-001 and
  FR-002, which spec §5 already requires.

**Unattended encryption (US2)**

- **FR-008**: `encrypt` MUST NOT ask for a file password when the user gives recipients.
- **FR-009**: Each command that needs a secret MUST accept it from a non-interactive input that does
  not expose it in the process argument list (for example, a file or stdin).
- **FR-010**: `encrypt` MUST accept a raw recipient public key with a `--recipient-key` flag. The
  value is the base64 key or a path to a file that contains it. The flag is repeatable, and it can
  be combined with `--recipient`. The host does not need a key database entry for the key.
- **FR-011**: The SDK MUST let a consumer encrypt to a raw public key without a key database on disk.
- **FR-012**: The CLI and the SDK MUST reject an invalid recipient public key with a usage error
  before they write output.

**Error classes and exit codes (US3)**

- **FR-013**: The CLI MUST exit with the codes in `docs/format-spec.md` §Governance item 5:
  0 success, 1 parse or usage, 2 tamper, 3 not a recipient, 4 wrong file password.
- **FR-014**: A wrong file password MUST give the same error class for the in-memory and the stream
  framing. Because method 3 has no key-check value, the message MUST say that the password is wrong
  or the file is damaged, and the exit code MUST be 4.

**Specification accuracy (US4)**

- **FR-015**: `docs/format-spec.md` MUST correct the 5 spec errors in review item F8. It MUST add
  v1 stream pseudocode, the frame-level tamper contract, and a §Limitations entry for v1 truncation.
  It MUST add a complete, reimplementation-grade section for the new container version.
- **FR-016**: The committed vectors MUST include at least one v1 chunked stream, and vectors for
  each method and framing of the new container version. This addition is a format-governance event
  under Principle III (spec update and byte-exactness re-verification).
- **FR-017**: The `encrypt` help text and the code comments that mention "version 2" MUST match the
  current behavior.

**SDK, files, and tooling (US5-US7)**

- **FR-018**: `Client.EncryptStream` and `Client.DecryptStream` MUST encrypt and decrypt between a
  caller's reader and writer, without temporary files. They MUST apply the same rules as the file
  path (FR-001 to FR-006, FR-014). `DecryptStream` MUST authenticate each chunk before it writes
  that chunk. Because a stream writer cannot take back written bytes, the method documentation
  MUST tell the caller to discard all output when the method returns an error.
- **FR-019**: Each output file MUST be written through a temporary file with a random name in the
  output directory, created exclusively. The cleanup MUST find stale files of all kinds.
- **FR-020**: The lint configuration MUST flag explicit error discards, with a short documented
  allow list. Each remaining discard in non-test code MUST be handled or added to the allow list.
- **FR-021**: The CI secret scan MUST pass on the committed tree without a weaker pattern.

**New container version (US8)**

- **FR-022**: The new version MUST bind the ephemeral public key and the recipient public key into
  the X25519 key derivation, for single-recipient and multi-recipient files.
- **FR-023**: New-version headers MUST NOT contain a field that depends on a recipient public key
  (no fingerprint hint and no recipient key ID). The decryptor MUST try each recipient block with
  each local key, inside the existing 16-recipient limit.
- **FR-024**: The new version MUST derive file-password keys with the memory-hard KDF and the
  parameters that protect private keys at rest. The KDF parameters MUST be in the authenticated
  header.
- **FR-025**: The decryptor MUST choose the rules from the authenticated version byte only. An
  unknown version MUST fail with a clear parse error. A downgrade (new-version content under a v1
  version byte, or the reverse) MUST fail and MUST NOT write plaintext. The failure class is the
  one that the target version's rules give (see contracts/format-v2.md §Tamper contract).
- **FR-026**: The governance section of the spec MUST record the new version, its byte value, and
  the freeze of the new version.
- **FR-027**: The single-frame framing (files under 1 MiB) MUST use the same version and the same
  KDF and recipient rules as the stream framing.

### Key Entities

- **Stream frame**: chunk length, chunk nonce, ciphertext with tag. In v1 the index is implicit
  (order). In the new version, each frame is also authenticated as final or not final.
- **Container version**: `0x01` (frozen, read-only after this feature) or the new version (written
  by default).
- **Staged output**: a temporary file that becomes the output file only on an explicit commit.
- **Error class**: tamper, not a recipient, wrong password, usage. Each maps to one exit code.
- **Recipient public key**: 32-byte X25519 key, given raw, by key ID, or by CKD lookup.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All 4 frame-level manipulations that v1 can detect (swap, repeat, remove, forged
  length) fail in 100% of runs. Each leaves 0 bytes at the output path.
- **SC-002**: A decryption that fails at any chunk leaves 0 bytes at the output path.
- **SC-003**: Decryption of a 28-byte forged file uses less than 1 MiB of extra memory.
- **SC-004**: An encryption to a public key succeeds with no terminal and no key database, in one
  command or one SDK call.
- **SC-005**: Each of the 5 exit codes has one passing CLI test, and the observed codes match the
  spec table 5 of 5.
- **SC-006**: Each pseudocode block in the spec gives the same result as the reference code for the
  committed vectors. The v1 chunked framing has at least 1 vector. The new version has at least 1
  vector for each method and each framing.
- **SC-007**: 0 exported SDK methods always fail. The SDK stream methods round-trip a 10 MiB input
  with no temporary file.
- **SC-008**: The full CI task set passes on a clean checkout, and a new silent discard fails lint.
- **SC-009**: All files in the existing vector set and all existing tests still pass.
- **SC-010**: A new-version stream truncated at each of its chunk boundaries fails in 100% of cases.
- **SC-011**: A new-version recipient header has 0 fields that change when only the recipient public
  key changes, apart from the ephemeral key and the wrapped key material.

## Assumptions

- The attached patch `0001-stream-frame-integrity.patch` is a starting point for FR-001, FR-002,
  and FR-003. Its oversized-length test does not detect the allocation and needs a stronger check.
  Its skipped truncation test is replaced by real new-version tests (FR-006).
- The nonce check is inside v1: spec §5 already requires derived nonces, and the encoder has always
  written them (Principle III).
- The SDK no-database path uses the existing pure-Go SQLite driver in memory mode, so no key
  database file is created and no new dependency is needed.
- The non-interactive secret inputs follow the existing flag names: `--password-file` for a file
  password and `--key-passphrase-file` for a key passphrase. The value `-` reads from stdin. The
  existing `MDSTN_KEY_PASSPHRASE` variable stays supported.
- The new version byte is `0x03`, not `0x02`. Spec line 36 says that a "v2" was retired before
  release. A new meaning for `0x02` could make an old pre-release file look valid. The spec still
  calls the new container "format v2". Governance item 2 is changed to match (FR-026).
- The new version is the default for every new file. There is no option to write v1. Consumers
  outside this module that read `.mdstn` files (for example, the web client) need new-version read
  support before they can read files from this release. This is a rollout dependency, not a
  requirement of this feature.
- The new-version construction follows published designs (STREAM final-chunk flag, age or HPKE key
  binding). The plan selects the exact construction. It uses no new dependency.
- The fix for V3 changes the test fixture (for example, the fixture reads its password from a
  generated value). The scan pattern stays as strict as it is now.
