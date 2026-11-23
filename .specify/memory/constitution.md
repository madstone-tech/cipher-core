<!--
Sync Impact Report
- Version change: 2.0.0 → 2.0.1 (PATCH: wording)
- Modified principles: III. One Container Format (records the freeze tag `v0.3.0`)
- Reason: the first release tag that ships `0x03` is `v0.3.0` (2026-11-08). The freeze rule is
  unchanged; only the tag is now named.
- Earlier: 1.0.0 → 2.0.0 (MAJOR, feature 002): `0x01` dropped, one format `0x03`.
- Added / removed sections: none
- Deferred TODOs: none
-->

# cipher-core Constitution

## Core Principles

### I. Inward Dependency Flow

Dependencies MUST point inward: entities ← usecases ← adapters ← delivery
(`internal/core/entities`, `internal/core/usecases`, `internal/adapters/*`, `internal/mcp`, `cmd/`).
Cross-layer calls MUST go through the interfaces in `internal/core/usecases/ports.go`. The public
re-export of those interfaces is `pkg/cipherports`.

Rationale: the core is a library that other applications embed. Each layer stays testable alone.

### II. No Commercial Surface

The core MUST NOT import the app-side delivery tree (`internal/{server,api,web,entitlement}`).
The core MUST NOT contain plan catalogs or billing. Feature checks resolve through
`cipherports.PlanFeatureResolver`, which the consuming application wires.
`TestMirrorBoundary` and the CI boundary gate enforce this rule.

Rationale: the module is public under BSL 1.1. Commercial logic belongs to the consumer.

### III. One Container Format

The project has one container format, version byte `0x03`, specified in `docs/format-spec.md`.
`0x01` and `0x02` are retired: decoders MUST reject them with "unsupported version". The format
freezes at the first release tag that ships it: `v0.3.0` (2026-11-08). After that tag, a change MUST NOT alter container
semantics under `0x03`, and any semantic change (method byte, required header field, AAD rule, MAC,
framing) MUST ship as a new version byte with its own spec section and test vectors. Before that
tag, a change needs a spec-kit feature, a spec update, and one vector regeneration.

Test vectors in `internal/testdata/` are canonical and normative. Contributors MUST NOT hand-edit
them. Generate them with
`CIPHER_REGENERATE_VECTORS=1 go test -run TestGenerateVectors ./internal/adapters/crypto/`.
Each generation is a format-governance event: update the spec and re-verify byte-exactness.

Rationale: other implementations depend on byte-exact, stable output.

### IV. Stable Public SDK Surface

The surface of `pkg/cipher` and `pkg/cipherports` is frozen. Each addition, removal, or signature
change MUST state its justification and MUST ship with a minor version bump. The public surface
MUST NOT export methods that always fail.

Rationale: consumers build against the SDK. Silent breaks and stub methods cost them time.

### V. Crypto and Error Discipline

Crypto MUST use the Go standard library and `golang.org/x/crypto` first. A new dependency MUST
state its justification. Secret comparisons MUST use `crypto/subtle`. Code MUST handle every error
(no silent `_ =` or `_, _ =`) except in documented best-effort cleanup. A failed decryption MUST
NOT publish plaintext. Error classes (tamper, not-a-recipient, wrong password, usage) MUST stay
separate from end to end, up to the CLI exit code.

Rationale: users act on what the tool reports. A wrong error class or partial output causes data loss.

## Security and Platform Constraints

- The build MUST be CGO-free. The module has no JS/CSS build pipeline.
- Observability is opt-in and lives in the consuming application. The core MUST NOT carry telemetry
  dependencies.
- Inputs from files are untrusted. A parser MUST bound each allocation before it reads the data.
- Output files MUST be written to an unpredictable temporary path and published only on success.
- Public files MUST NOT contain private-repository references or secrets.

## Quality Gates

- `task ci` (fmt, lint, vet, test, build) MUST pass with zero warnings (gofumpt, golangci-lint).
- `task fork-boundary` MUST pass.
- Each security fix MUST include a regression test that fails before the fix and passes after it.
- Tests MUST check consumer-visible behavior: outputs, error classes, exit codes, files on disk.
- A change to `docs/format-spec.md` MUST keep the pseudocode consistent with the code and vectors.

## Governance

This constitution takes priority over other project practices. `AGENTS.md` gives the runtime
guidance for contributors and agents, and it MUST stay consistent with this document.

- Amendments: open a change that edits this file. State the reason and the version bump.
- Versioning: MAJOR for removal or redefinition of a principle. MINOR for a new principle or a
  material expansion. PATCH for wording changes.
- Compliance: each plan (`/speckit-plan`) MUST include a Constitution Check against Principles I-V.
  Each review MUST confirm the check.

**Version**: 2.0.1 | **Ratified**: 2026-11-04 | **Last Amended**: 2026-11-08
