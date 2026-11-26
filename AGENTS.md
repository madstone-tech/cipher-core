# cipher-core — Agent & Contributor Guide

Guidance for AI coding agents and human contributors.

## What this is

The zero-knowledge encryption core of Madstone Cipher as a standalone Go module:
domain entities, usecases, crypto/SQLite/CKD/CLI/logging adapters, MCP server, the CLI command
surface, and the public SDK (`pkg/cipher`) + port surface (`pkg/cipherports`).

- **Module:** `github.com/madstone-tech/cipher-core`
- **Go:** 1.27.1 · **License:** BSL 1.1 (→ Apache 2.0 three years after each release)
- No CGO (every package builds with `CGO_ENABLED=0`). The one sanctioned exception is the app
  framework that `gomobile bind` builds from `pkg/mobile`; see the constitution. No JS/CSS build
  pipeline. The format spec lives in `docs/format-spec.md`; the CKD protocol in
  `docs/ckd-protocol.md`.

## Build & test (Taskfile)

```bash
task build             # go build ./...
task test              # go test ./... -count=1
task lint              # golangci-lint run
task fmt               # gofumpt -w .
task vet               # go vet ./...
task ci                # fmt + lint + vet + test + build
task fork-boundary     # boundary gate (core imports nothing app-side)
```

## Architecture (Clean / "Loko" pattern)

Strict inward dependency flow: **entities ← usecases ← adapters ← delivery** (`internal/core/entities`,
`internal/core/usecases`, `internal/adapters/*`, `internal/mcp`, `cmd/`). Cross-layer calls go through
interfaces in `internal/core/usecases/ports.go`; the PUBLIC re-export is `pkg/cipherports` (plus the
auth-context types that live there canonically now).

Non-negotiables:

- **Core never imports the app-side delivery tree** — `internal/{server,api,web,entitlement}`
  and the server-side adapters do not exist here. Enforced by `TestMirrorBoundary` + CI.
- **Core has no commercial surface**: no plan catalogs, no billing. `HasFeature` resolves via
  `cipherports.PlanFeatureResolver`, which the CONSUMING app wires.
- SDK surface (`pkg/cipher`) is frozen; changes need justification and a minor bump.
- Crypto uses Go stdlib + `golang.org/x/crypto` first; new dependencies need justification.
- ONE container format, version byte `0x03` (`docs/format-spec.md`; constitution Principle III).
  `0x01` and `0x02` are retired and MUST stay rejected. The format freezes at the first release tag
  that ships it; after that, a semantic change needs a new version byte. The header MAC is verified
  (constant time) before any body byte is decrypted.
- A supplied key passphrase is always checked; the session cache serves only empty passphrases.
  SDK calls keep secrets per call (no shared prompter state).
- With `--json`, stdout holds exactly one JSON value; logs and progress go to stderr. Key JSON never
  contains wrapped private keys or salts. No output may contain a value derived from a password.
- Header fields are sender-controlled: never use one as a path (not even a validated
  `original_filename`). A default output path is derived from the input path only, never replaces a
  file (`FileHandler.WriteStreamExclusive`), and no path may be the input or the key database
  (`usecases.CheckOutputPath` with the key-store DSNs, `ProtectKeyStore`; wire it for every new
  write path). The guard is BY FOLDER: no output in the configured or resolved (symlink) folder of
  the key database, or in a folder holding a hard link to it. SQLite replays a created
  `<db>-journal` into the database, and name matching cannot copy file-system case/Unicode folding.
  Tests MUST keep their DB in its own folder (`keyDB` in `cmd/clibinary_test.go`).
- No write path replaces a file it did not get an explicit path for (`encrypt`, `decrypt`,
  `backup`, MCP). MCP tools never write to a caller-chosen path; in MCP mode only the protocol
  layer (`internal/mcp.Serve`) writes to stdout.
- Session-cache TTLs come from configuration (`SetKEK` with ttl 0 = store default). Cache a KEK and
  count key usage only after the file authenticates and the output is published.
- Handle every error (no silent `_ =`); errcheck `check-blank` enforces it. A justified best-effort
  discard needs `//nolint:errcheck // best-effort: <reason>`. `crypto/subtle` for secret compares;
  gofumpt/golangci zero-warning.
- Output files go through `usecases.StagedWriter` (`Commit` on success, `Abort` on every error path).
  A failed or cancelled operation MUST NOT leave a file at the output path.
- Observability is opt-in and lives in the CONSUMING app; core carries no telemetry deps.
- Test vectors (`internal/testdata/`) are canonical here and normative per `docs/format-spec.md`.
  NEVER hand-edit fixtures; add vectors with
  `CIPHER_REGENERATE_VECTORS=1 go test -run TestGenerateVectors ./internal/adapters/crypto/`.
  The generator is append-only (existing fixtures stay byte-identical). Treat any addition as a
  format-governance event (spec update + byte-exactness re-verification).