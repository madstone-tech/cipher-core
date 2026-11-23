# cipher-core — the zero-knowledge encryption core

The format/crypto/storage core of [Madstone Cipher](https://madstone.io) as a
standalone Go module.

- **Module**: `github.com/madstone-tech/cipher-core`
- **License**: BSL 1.1 (converts to Apache 2.0 three years after each release) — see [LICENSE](./LICENSE)

## What lives here

| Package | Contents |
|---|---|
| `internal/core/entities` | Domain types: `IdentityKey`, `KeyMetadata`, `EncryptedFile`, `RecipientBlock`, sentinels |
| `internal/core/usecases` | Application logic (encrypt/decrypt/keys/CKD/recovery) + `ports.go` port interfaces |
| `internal/adapters/crypto` | The crypto engine: X25519/HKDF/AES-256-GCM, the header-AEAD binding, `.mdstn` format codec, fuzz + tamper-matrix tests |
| `internal/adapters/sqlite` | SQLite repositories (identity keys, CKD cache, recovery, shared-key policies) |
| `internal/adapters/ckd` | CKD discovery client |
| `internal/adapters/cli` | File handler (staged writes: random exclusive temp file, published only on success) |
| `internal/adapters/logging` | `SimpleLogger` |
| `internal/mcp` | MCP server on stdio (7 tools; no key creation or deletion, no caller-chosen write paths) |
| `pkg/cipher` | **The public SDK** — `NewLocal`/`New`, `Client`, aliased types |
| `pkg/cipherports` | Public port interfaces + auth-context types; `PlanFeatureResolver` hook |
| `cmd/` | The CLI command surface (`mdstn-cipher` entrypoint) |
| `internal/testdata/` | Canonical format test vectors (`vectors.json` + `.mdstn` fixtures) — normative per `docs/format-spec.md` |

## Format

The `.mdstn` container has **one format**, version byte `0x03`. The body starts with a header MAC
that commits the header to the file key, so every recipient gets the same plaintext or an error.
Each stream chunk is authenticated with its index and a final-chunk flag, so truncation and
reordering fail. Recipient blocks bind both public keys into the key derivation and store no
recipient identifier. File passwords use Argon2id. Version bytes `0x01` and `0x02` are retired:
the tool rejects them with "unsupported version". The reimplementation-grade specification is
[`docs/format-spec.md`](docs/format-spec.md). §Error Classes, §Tamper Contract, and §Governance
are normative.

CKD (email-based public-key discovery) is documented in [`docs/ckd-protocol.md`](docs/ckd-protocol.md).

## CLI automation

The CLI runs without a terminal:

```sh
mdstn-cipher encrypt snap.db --recipient-key "$PUB" -o snap.mdstn        # raw X25519 public key
mdstn-cipher encrypt big.tar --password-file /run/secrets/pw              # file password from a file
mdstn-cipher decrypt snap.mdstn --key-passphrase-file - -o snap.db < pw   # key passphrase from stdin
```

Exit codes (`docs/format-spec.md` §Error Classes): `0` success, `1` usage or parse error,
`2` tampered file, `3` not a recipient, `4` wrong file password. A failed or cancelled operation
leaves no file at the output path. With `--json`, stdout holds exactly one JSON value, and logs
and progress go to stderr. Without `-o`, `decrypt` writes to the input path without `.mdstn` and never
replaces an existing file (`--force` allows it). It never uses the sender's file name from the
header as a path, and it never replaces the input. `encrypt` never replaces `<file>.mdstn` without `--force`. `backup` writes to
`~/.mdstn/backups/` and never replaces a file. The format does not authenticate the sender.

`mdstn-cipher mcp` runs an MCP server on stdio (protocol versions 2025-06-18 and 2024-11-05). Its tools never replace a file, and none of them writes to a path that the caller
chooses, except `encrypt_file` and `decrypt_file` with their no-replace default paths.

## Using as a Go module

```sh
go get github.com/madstone-tech/cipher-core
```

The SDK surface is `pkg/cipher` (`cipher.NewLocal`, `cipher.New`, `Client.EncryptStream`,
`Client.DecryptStream`). Use `Config{DBPath: cipher.InMemory}` to encrypt to a public key without a
key database on disk. Port interfaces for wiring consuming apps are in `pkg/cipherports`.

## Build & test

```sh
task ci            # fmt + lint + vet + test + security + build + boundary
task verify-sdk    # prove pkg/cipher works from a throwaway external module
task verify-facade # assert no internal type leaks through pkg/cipher
```

Requires Go 1.27.1+, `golangci-lint`, `gofumpt`, `task`.

## Releasing

Tag `vX.Y.Z` and push — `.github/workflows/release.yml` runs GoReleaser:
cross-compiled `mdstn-cipher` binaries (linux/darwin/windows, amd64/arm64 +
macOS universal), tar.gz/zip archives, checksums, SBOM, keyless cosign
signing (`.sigstore.json` bundles), GHCR multi-arch Docker images
(`ghcr.io/madstone-tech/mdstn-cipher-core`), and SLSA build-provenance attestations
(auto-enabled on public repos).

Local snapshot (no publish): `task release-snapshot`.

## Tag conventions

- Tags are cut **as-needed** when this module's code changes.
- `v0.1.0` = the initial cut. Patches bump patch; additive surface bumps minor. A format change needs a new container version byte and is governed by [`docs/format-spec.md`](docs/format-spec.md) §Governance.

## Development workflow

Feature branches, conventional commits — see [AGENTS.md](AGENTS.md).