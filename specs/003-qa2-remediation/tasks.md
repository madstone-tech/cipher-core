# Tasks: QA Verification 2 Remediation

**Input**: `specs/003-qa2-remediation/spec.md`. Plan: the decisions are in the spec (FR-001 to
FR-009); no separate research was needed. Constitution check: Principle III allows the header rule
changes before the first release tag; Principle IV changes (`DecryptInput.Overwrite`,
`FileHandler.WriteStreamExclusive` is internal) ship in v0.3.0.

**Tests**: REQUIRED. Write each test first and confirm it fails.

## Phase 1: US1 + US2 (P1)

- [X] T001 [US1] Tests first: `entities.ValidOriginalFilename` table test; decoder rejects `../x`, `/abs`, `a\b`, `c:x`, `..`, `.`, NUL, control characters, 256 bytes; encoder rejects them; usecase test: default output path is in the input directory, an existing file is not replaced, `Overwrite` replaces it; an SDK `OriginalFilename` of `../x` fails before output
- [X] T002 [US1] `ValidOriginalFilename` in internal/core/entities/encrypted_file.go; call it in the decoder and encoder (internal/adapters/crypto/mdstn_format.go)
- [X] T003 [US1] `WriteStreamExclusive` in the FileHandler port and the CLI adapter: Commit links the temp file to the final path (fails with `fs.ErrExist`), falls back to check-then-rename where links are not supported; fakes updated
- [X] T004 [US1] DecryptFile default output path (FR-003) and exclusive publication (FR-004); `DecryptFileRequest.Overwrite`; encoder: SDK `OriginalFilename` validated (usage error), local base name omitted when not safe (internal/core/usecases)
- [X] T005 [US1] CLI `decrypt --force`; SDK `DecryptInput.Overwrite`; MCP unchanged (never overwrites)
- [X] T006 [US2] Tests first: no output of CLI text, CLI JSON, SDK, or MCP contains `sha256(password)`
- [X] T007 [US2] Empty fingerprint for method 3 (internal/core/usecases/encrypt_file.go); CLI prints no empty fingerprint line

## Phase 2: US3 (P3)

- [X] T008 [US3] Tests first: header numbers, surrogates, NaN, depth (internal/adapters/crypto)
- [X] T009 [US3] Go header pre-scan with `jsontext` (depth ≤ 8, integer numbers in [0, 2^53 − 1]); spec Python parse_header enforces the same rules
- [X] T010 [US3] Record key usage only after the MAC and the body authenticate (internal/core/usecases/decrypt_file.go), with a test
- [X] T011 [US3] Negative fixtures `bad-filename` (`../x`) and `nan-in-header`; conformance and tamper tests also run every vector and negative fixture through `DecryptFile.DecryptStream`
- [X] T012 [US3] Run the spec Python against every vector and negative fixture; record the result

## Phase 3: US4 (P3) and polish

- [X] T013 [US4] docs/format-spec.md: safe base name rule, output-path rule for decryptors, JSON rules, §Limitations "No sender authentication", §Container Version note on pre-release `0x03` builds and v1
- [X] T014 [US4] `CreateKey` godoc: starts a session, see `Lock`/`LockAll`
- [X] T015 CHANGELOG: Q1 behavior change, Q2 exposure note, Q3 and v1 notes; README/AGENTS output rules
- [X] T016 `task ci`, external SDK proof, QA cases on the built binary; record results in specs/003-qa2-remediation/quickstart.md; commit
