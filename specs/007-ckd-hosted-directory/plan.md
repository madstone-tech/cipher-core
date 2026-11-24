# Implementation Plan: CKD hosted-directory client support (keys.mdstn.dev)

**Branch**: `007-ckd-hosted-directory` | **Date**: 2026-11-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/007-ckd-hosted-directory/spec.md`

## Summary

Add client-side support for the hosted CKD server (keys.mdstn.dev): a Bearer
`kd_token` on publish/unpublish (flag `--kd-token`, env `KD_TOKEN`, default
server `https://keys.mdstn.dev`), the additive rotation publish contract
(fingerprint + poc, 409 surface), ed25519 response-signature verification with
key-id pinning, `key_type` handling with a `(email, key_type)`-keyed TOFU cache,
an updated protocol document, and a byte-exact cross-repo wire fixture test.
Target release: v0.4.0. No container-format change (Constitution III untouched).

## Technical Context

**Language/Version**: Go 1.27.1 (module `github.com/madstone-tech/cipher-core`; toolchain go1.27.4)

**Primary Dependencies**: Go stdlib (crypto/ed25519, net/http, encoding/*), `golang.org/x/crypto` — no new dependencies; `github.com/spf13/cobra` (existing, for CLI flags)

**Storage**: local SQLite key DB + `ckd_cache` table (existing adapter, schema extended, backward compatible); no new storage

**Testing**: `go test ./... -count=1` via `task test`; contract tests against the pinned fixture from `../ckd-server/test/contract/fixtures/`; `task ci` gate (gofumpt + golangci-lint + vet + test + build) and `task fork-boundary`

**Target Platform**: darwin/arm64 + linux (CLI binary and SDK); CGO-free build

**Project Type**: library + CLI (clean-architecture Go module with cobra CLI delivery)

**Performance Goals**: signature verification adds ≤ 1 ms per lookup (ed25519 verify is ~50 µs); no lookup-path allocation growth beyond one 32-byte key read

**Constraints**: secret comparisons constant-time (`crypto/subtle`); no token/key material in logs or JSON output; every error handled (errcheck check-blank); SDK surface changes need justification (Constitution IV)

**Scale/Scope**: 5 touch areas: `cmd/keys*.go`, `internal/adapters/ckd/client.go`,
`internal/adapters/sqlite/ckd_cache.go`, `internal/core/usecases/{ports,lookup_key}.go`,
`docs/ckd-protocol.md` + fixture test. ~8 files, all inside the module.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Inward Dependency Flow | PASS | all changes live in adapters/usecases/cmd; no delivery imports |
| II. No Commercial Surface | PASS | lookup stays free/ungated; token is a user credential, not an entitlement |
| III. One Container Format | PASS | transport- and publish-level only; `0x03` untouched, no vector regeneration |
| IV. Stable Public SDK Surface | JUSTIFIED CHANGE | `CKDCacheEntry` gains `KeyType`; cache cache keyed by `(email, key_type)`. Justification: the protocol's forward-compatibility note is now exercised by a live server; minor bump v0.4.0 carries it per the rule. Recorded for v0.4.0 (T018): `usecases.CKDCacheEntry.KeyType` (new field), `CKDCacheRepository.Get/Delete` widened with a key-type argument, `CKDPublicKey.KeyType` (new field), `LookupKeyResponse.KeyType` (new field). Additive or widening only; no removals; `pkg/cipherports` aliases unchanged. |
| V. Crypto and Error Discipline | PASS | ed25519 via stdlib; `crypto/subtle` for key-id compares; new error classes (auth/conflict/integrity) kept separate to CLI exit codes; no silent `_ =` |

No violations → Complexity Tracking stays empty. Post-design re-check: PASS (design below adds
no layer jumps; SQLite migration is additive CREATE TABLE + ALTER, no destructive rebuild).

## Project Structure

### Documentation (this feature)

```text
specs/007-ckd-hosted-directory/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── ckd-wire.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
cmd/
├── keys.go              # Publish/Unpublish: token, Bearer header, default URL, rotation handling
├── keys_cobra.go        # --kd-token flag, env fallback, help text
└── exit.go              # (read-only reference) exit-code classes for new error kinds

internal/core/usecases/
├── ports.go             # CKDCacheEntry.KeyType; (email, key_type) Get/Set/Delete signatures widened
└── lookup_key.go        # cache keyed by (email, key_type); key type passthrough

internal/adapters/ckd/
├── client.go            # signature verify (ed25519, kid pin), key_type decode, publish rotation body
├── service_key.go       # pinned service public key + key id constants, key-id TOFU store
└── client_test.go       # fixture round-trip, tamper test, unknown-kid test

internal/adapters/sqlite/
├── ckd_cache.go         # schema: key_type column, composite key, backward-compatible migration
└── ckd_cache_test.go

internal/core/entities/  # (read-only reference) KeyTypeX25519 constant reuse

cmd/keys_publish_contract_test.go  # 409/conflict matrix against httptest stub

docs/
└── ckd-protocol.md      # signed responses, rotation fields, service key doc

internal/testdata/
└── ckd/lookup.json      # byte-exact copy of ckd-server fixture (normative, never hand-edited)
```

**Structure Decision**: single-module layout as-is; changes confined to the existing
clean-architecture slots (adapters for HTTP/SQLite, usecases for cache policy, cmd for CLI).
No new packages except `service_key.go` inside the existing `internal/adapters/ckd`.

## Complexity Tracking

> Fill ONLY if Constitution Check has violations that must be justified.

*(empty — no violations)*
