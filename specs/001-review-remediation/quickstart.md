# Quickstart: validate the remediation

Prerequisites: Go 1.27, `task`, `golangci-lint` 2.15, Python 3 (for frame edits). Run from the
repository root.

## 1. Gates

```sh
task ci              # fmt, lint, vet, test, build: all pass, zero warnings
task fork-boundary   # passes
bash tests/external-sdk/run.sh
```

Expected: every command exits 0. The CI secret scan step passes (V3).

## 2. Frame tampering (US1, US8)

Run the reproduction script from the review appendix
(`cipher-core-review-2026-11-04/cipher-core-review.md`, §Appendix) against the new binary, and add
these cases: truncate without terminator, bytes after the terminator, version byte flip.

| Case | Expected exit | Output file |
|---|---|---|
| swap, dup, remove, lateflip, forged length | 2 | none |
| trunc + terminator (new file, v2) | 2 | none |
| trunc + terminator (committed v1 chunked vector) | 0 (documented v1 limitation) | present |
| unchanged | 0 | byte-identical |

The regression tests are `TestDecryptStreamRejectsFrameManipulation` (v1 and v2 table) and
`TestStreamV2Truncation` in `internal/adapters/crypto/`, plus the usecase test with the real
`cli.FileHandler` that checks for no file at the output path.

Observed on 2026-11-04 (branch `001-review-remediation`, 1.25 MiB password file, 20 chunks):

| Case | Expected exit | Observed exit | Output file |
|---|---|---|---|
| swap frames 0 and 1 | 2 | 2 | none |
| frame 0 repeated 20 times | 2 | 2 | none |
| remove frame 5 | 2 | 2 | none |
| bit flip in chunk 10 | 2 | 2 | none |
| forged length `0xFFFFFFF0` | 2 | 2 | none |
| truncate to 3 frames + terminator (v2) | 2 | 2 | none |
| truncate to 3 frames, no terminator | 2 | 2 | none |
| 1 byte after the terminator | 2 | 2 | none |
| version byte `0x03 → 0x01` | 2 | 2 | none |
| unchanged | 0 | 0 | byte-identical |
| wrong password | 4 | 4 | none |
| v1 chunked vector, unchanged | 0 | 0 | present |
| v1 chunked vector, truncate + terminator | 0 (v1 limitation) | 0 | present |
| v1 chunked vector, swap frames 0 and 1 | 2 | 2 | none |

## 3. Unattended encryption (US2)

```sh
D=$(mktemp -d)
mdstn-cipher --db "$D/a.db" keys create --key-passphrase-file <(printf 'pw\n') --yes
PUB=...   # base64 public key of the new key, from `keys list --json` (field name: see cmd/keys.go)
mdstn-cipher --db "$D/b.db" encrypt snap.db --recipient-key "$PUB" -o snap.mdstn </dev/null
mdstn-cipher --db "$D/b.db" keys list --json   # the encrypting side holds 0 keys
mdstn-cipher --db "$D/a.db" decrypt snap.mdstn --key-passphrase-file <(printf 'pw\n') -o out.db
cmp snap.db out.db
```

Expected: no prompt, exit 0 for each step, `cmp` is silent. `encrypt --recipient-key AAAA` exits 1
before it writes output.

## 4. Exit codes (US3)

`go test ./cmd -run TestExitCodes` runs one CLI case for each code 0-4. A wrong password on a
2 MiB and on a 1 KiB password file both exit 4 with the same message.

## 5. SDK (US2, US6)

`go test ./pkg/cipher -run 'TestStream|TestInMemory'`:

- `EncryptStream` → `DecryptStream` round-trips 10 MiB through `bytes.Buffer`, and no file is
  created in the working directory or in `$HOME/.mdstn`.
- `Config{DBPath: cipher.InMemory}` encrypts to a raw public key with no file on disk.

## 6. Spec and vectors (US4)

`go test ./internal/adapters/crypto -run TestVectorsConformance` verifies the v1 single-frame,
v1 chunked, and v2 vectors (each method and framing). Each pseudocode block in
`docs/format-spec.md` is checked by hand against one vector.

## 7. Temporary files (US5)

`go test ./internal/adapters/cli -run TestStaged` checks: a planted symlink at the old `.tmp`
path stays unchanged, `Abort` leaves no file, and stale `*.mdstn-partial` files older than one
hour are removed.
