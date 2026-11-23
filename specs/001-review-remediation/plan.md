# Implementation Plan: Review Remediation (2026-11-04)

> **Superseded in part by `specs/002-qa-remediation/`** (2026-11-05). The app was not released, so
> feature 002 removed the `0x01` format (no v1 read path, no v1 vectors) and changed `0x03`
> before its first tag: header MAC, canonical keys, strict base64, canonical final frame. Read
> the v1 and format-v2 statements below as history.

**Branch**: `001-review-remediation` | **Date**: 2026-11-04 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-review-remediation/spec.md`

## Summary

Fix the 11 review findings and 3 verification findings. There are four parts:

1. Make the v1 decoder stricter inside the frozen format: derived-nonce check, length bound, and
   EOF after the terminator.
2. Stage all output files and publish them only on success.
3. Ship container version `0x03` (format v2) as the default for new files. It has an authenticated
   final chunk, public keys bound into the HKDF, no recipient hints, and Argon2id for file
   passwords.
4. Fix the CLI, SDK, spec, lint, and CI: exit codes, non-interactive inputs, `--recipient-key`,
   working SDK streams, an in-memory SDK key store, `check-blank`, and the secret scan.

## Technical Context

**Language/Version**: Go 1.27.1 (`go.mod`). The local toolchain is go1.27.3.

**Primary Dependencies**: Go stdlib (`crypto/aes`, `crypto/cipher`, `crypto/rand`), `golang.org/x/crypto` (curve25519, hkdf, argon2, pbkdf2), `modernc.org/sqlite` (CGO-free), cobra. No new dependency.

**Storage**: SQLite key store (`~/.mdstn/cipher.db`), or `:memory:` for the SDK. `.mdstn` files.

**Testing**: `go test ./...`, the vector conformance suite, the tamper matrix, `tests/integration`, `tests/external-sdk/run.sh`.

**Target Platform**: Linux, macOS, Windows CLI, Kubernetes Jobs (no TTY), Go SDK consumers.

**Project Type**: Go library, CLI, and MCP server.

**Performance Goals**: stream memory stays O(chunk size). No full-file read on decryption (today `decrypt_file.go:77` reads the whole file). Throughput within 10% of v1 for a 100 MiB file.

**Constraints**: v1 semantics frozen. Existing vectors byte-identical. CGO-free. Zero lint warnings.

**Scale/Scope**: about 25 production files across `internal/adapters/{crypto,cli}`, `internal/core/{entities,usecases}`, `cmd/`, `pkg/{cipher,cipherports}`, plus `docs/format-spec.md`, `.golangci.yml`, vectors, and tests.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Check | Result |
|---|---|---|
| I. Inward dependency | New sentinels (`ErrWrongPassword`, `ChunkAuthError`, `ErrInvalidRecipientKey`) are in `entities`. `StagedWriter` is in `usecases/ports.go`. Adapters implement it. `cmd` maps errors to exit codes. | Pass |
| II. No commercial surface | No plan, billing, or app-side import. `task fork-boundary` stays in the gates. | Pass |
| III. Frozen format v1 | v1 semantics do not change. The stricter v1 checks are already required by spec §5 (derived nonce) and by GCM bounds. The new version uses a new byte (`0x03`) and its own spec section and vectors. Existing fixtures are not rewritten (the generator writes only missing files). | Pass, governance event recorded (FR-026) |
| IV. Stable SDK surface | Public changes: `CryptoEngine` stream and KEM methods take `version`. `DeriveFileKeyArgon2id` and `FileEncoder.DecodeHeader` are new. The SDK stream signatures change, `InMemory` and `ErrWrongPassword` are new. Justified in `contracts/sdk.md`. Ships as `v0.3.0` with a changelog. | Pass with justification (see Complexity Tracking) |
| V. Crypto and error discipline | Stdlib and x/crypto only. Error classes stay separate up to the exit code. No published partial output. `check-blank` enforces the error rule. | Pass |

Post-design re-check (after Phase 1): no new violations. The data model and contracts keep v1
read-only, and they add no dependency.

## Project Structure

### Documentation (this feature)

```text
specs/001-review-remediation/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── format-v2.md
│   ├── cli.md
│   └── sdk.md
├── checklists/requirements.md
└── tasks.md            # /speckit-tasks
```

### Source Code (repository root)

```text
internal/core/entities/        errors.go (new sentinels), encrypted_file.go (Version 3, KDFParams, Validate)
internal/core/usecases/        ports.go (StagedWriter, CryptoEngine, FileEncoder.DecodeHeader)
                               encrypt_file.go (v2 headers, stream core, Abort paths)
                               decrypt_file.go (header from reader, v1/v2 dispatch, trial unwrap, error classes)
internal/adapters/crypto/      aes.go (v1 strict decode, v2 stream), x25519.go (v2 HKDF), argon2id.go,
                               mdstn_format.go (v2 encode/decode), stream_v1_test_helpers_test.go (v1 encoder)
internal/adapters/cli/         file_handler.go (CreateTemp staging, Commit/Abort, dir cleanup)
internal/adapters/sqlite/      identity_key_repo.go (:memory: → SetMaxOpenConns(1))
internal/mcp/                  server.go (follows the usecase changes only)
cmd/                           mdstn-cipher/main.go, exit.go (ExitCode), encrypt*.go, decrypt*.go, keys*.go,
                               secretinput.go (--password-file, --key-passphrase-file), signal context
pkg/cipher/                    encrypt.go (stream methods), client.go (InMemory), aliases.go
pkg/cipherports/               ports.go (alias follows CryptoEngine)
internal/testdata/             new v1-chunked and v2 fixtures, vectors.json entries
docs/format-spec.md            F8 fixes, v1 stream pseudocode, §Limitations, v2 section, governance
.golangci.yml                  errcheck check-blank
tests/external-sdk/main.go     runtime password (V3)
tests/integration/             staged-output and exit-code scenarios
```

**Structure Decision**: keep the existing Clean layout. No new package. The v1 stream encoder
moves into a `_test.go` file, so production code cannot write v1.

## Implementation Phases (input for `/speckit-tasks`)

| Phase | Content | Depends on |
|---|---|---|
| A. Foundations | Sentinels, `StagedWriter` port + CLI adapter, `ExitCode` + signal context, `check-blank` config | — |
| B. v1 hardening (US1) | R1 checks, Abort on all 9 stream error paths, test with real `FileHandler` | A |
| C. Format v2 (US8) | Entities, encoder/decoder, v2 stream, v2 KDFs, trial unwrap, `DecodeHeader` streaming decrypt | A, B |
| D. CLI automation (US2, US3) | prompt condition, `--recipient-key`, secret-file flags, exit-code tests, wrong-password class | A, C (error classes) |
| E. SDK (US2, US6) | `InMemory`, stream methods on the usecase stream cores | C |
| F. Spec, vectors, docs (US4) | F8 fixes, pseudocode, tamper contract, v2 section, generator + fixtures, help text, changelog | C |
| G. Cleanup (US5, US7) | temp-file tests, triage of the 45 discards, V3 fixture, `task ci` | A-F |

## Risks

- **Rollout**: new files are v2. A reader outside this module (the web client) cannot read them
  until it adds v2 support. This is a release-note item, not a code change here.
- **Trial unwrap cost**: without hints, decryption can unwrap each local private key. The default
  key is tried first, and the session store caches KEKs.
- **Method 3 class**: header tampering on a password file reports exit 4, not 2. This is
  unavoidable without a key-check value, and it is documented.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Public `CryptoEngine` signature change (Principle IV) | v2 decoding needs the version for stream and KEM methods | Separate `*V2` methods keep two parallel APIs and a write-v1 path alive |
| SDK stream signature change (Principle IV) | The stubs take no recipients or password, so no working implementation fits them | Removal was rejected by the user (clarification Q3) |
