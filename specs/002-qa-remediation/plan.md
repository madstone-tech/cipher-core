# Implementation Plan: QA Remediation and Single Container Format

**Branch**: `002-qa-remediation` | **Date**: 2026-11-04 | **Spec**: [spec.md](spec.md)

## Summary

Make container `0x03` the only format, add a header MAC (key commitment), require canonical keys,
strict base64, and a canonical final frame. Remove all `0x01` code. Fix the key-handling and CLI
findings: checked passphrases, per-call SDK state, `keys create` JSON and TTY rules, clean JSON
stdout, a safe key DTO, labels, and results.

## Technical Context

**Language/Version**: Go 1.27.1. **Dependencies**: stdlib (`crypto/hmac`, `crypto/subtle`), `golang.org/x/crypto` (hkdf, curve25519, argon2). No new dependency.
**Storage**: SQLite key store (unchanged schema). **Testing**: `go test`, `-race`, vectors, tamper matrix, the Python pseudocode, CLI binary tests.
**Project Type**: Go library, CLI, MCP server. **Constraints**: CGO-free, zero lint warnings.

## Research and decisions

| # | Decision | Rationale | Rejected alternative |
|---|---|---|---|
| R1 | Keep version byte `0x03`. Reject `0x01` and `0x02` as retired. | Public `v0.2.x` modules wrote `0x01`. A reused byte gives wrong parses instead of a clear error. | Reset to `0x01`: ambiguous with old files. |
| R2 | Body = `header_mac(32) ‖ rest`. `mac_key = HKDF(file_key, info="mdstn-cipher/v2/header-mac")`, `payload_key = HKDF(file_key, info="mdstn-cipher/v2/payload")`, `header_mac = HMAC-SHA256(mac_key, headerAAD)`. | The age design. HMAC-SHA256 as a function of its key is collision resistant, so a header commits to one file key. The MAC is a key check, so a wrong password is exact and the chunk-0 relocation heuristic is deleted. | MAC inside the header JSON: circular. A key-committing AEAD: new dependency. |
| R3 | Recipient trial: unwrap CEK, then verify the MAC. Unwrap fails → next block or key. Unwrap succeeds and MAC fails → tamper (exit 2). | Only the file key's holder can make a MAC that verifies. A wrong MAC after a good unwrap is an attack. | Continue to the next block: hides the attack. |
| R4 | `ValidatePublicKey`: length 32, `pub[31] & 0x80 == 0`, little-endian `u < 2^255 − 19`, not low-order. Call sites: `EncryptFile` recipient planning (covers CLI raw key, local key, CKD, SDK, MCP). | One check at the usecase boundary covers every path. | Clear bit 255 silently: changes the salt, the owner still cannot decrypt. |
| R5 | Stream: when `n ≥ 1` frames, the final frame MUST have `len ≥ 17` (≥ 1 plaintext byte). | One encoding per plaintext. The encoder already writes this form. | Accept it: two encodings. |
| R6 | Base64: `base64.StdEncoding.Strict()` and reject any `\r` or `\n` before decode. | Go's decoder skips CR/LF. The spec reference rejects them. | — |
| R7 | N1: `resolvePrivateKey` uses the cached KEK only when the passphrase is empty. With a passphrase, derive, unwrap, and replace the cache entry. Wrong → fail. | The godoc already says this. | Compare the passphrase to a cached hash: a new secret at rest. |
| R8 | N8/FR-009: the SDK builds a per-call prompter from the call input. The shared `headlessPrompter` field is removed. `Client.Lock()` clears the session store. | Removes the race and shared-secret state. | A mutex: still shared state between callers. |
| R9 | N4: progress and logs go to stderr in JSON mode. The SDK default logger writes to stderr in all modes. | Stdout is the data channel. | — |
| R10 | N5: `keyJSON` DTO in `cmd` with snake_case tags, without wrapped keys and salts. | Logs are not a place for wrapped secrets. | — |
| R11 | N6: `MethodPassphrase = "passphrase-aes256"`. | v0.3.0 already changes the output. | One label per version: there is one version. |
| R12 | Vectors: delete all `0x01` fixtures and `js_*_v1` fixtures. Regenerate all `0x03` vectors once. Add edge lengths and negative fixtures (`vectors.json` `negative` array with `expect`). | The app is not released (user decision). | — |

## Constitution Check

| Principle | Check | Result |
|---|---|---|
| I | Changes stay in their layers. | Pass |
| II | No commercial surface. | Pass |
| III | **Amendment needed.** v1 is removed and `0x03` changes before its first release. | Pass after amendment to constitution v2.0.0 (T001): the single format freezes at the first tag that ships it. |
| IV | SDK changes: `Lock()`, `Version` fields, label value, prompter removal. Minor bump in v0.3.0 (same release). | Pass with justification |
| V | Exact error classes (R2, R3), per-call secrets (R8). | Pass |

## Project Structure

```text
internal/adapters/crypto/   mdstn_format.go (v1 removal, strict base64), aes.go (v1 removal, MAC, final frame),
                            x25519.go (ValidatePublicKey canonical, v1 KDF removal), pbkdf2/pbkdf code removal
internal/core/entities/     encrypted_file.go (Version 3 only, label), errors.go
internal/core/usecases/     encrypt_file.go (MAC, validation), decrypt_file.go (MAC, trial order, N1, v1 removal)
pkg/cipher/                 per-call prompter, Lock(), Version in results, comments
cmd/                        keys.go (N2, N3, N5), JSON stdout (N4), empty recipient (N7)
internal/adapters/cli/      progress reporter to stderr in JSON mode
internal/testdata/          regenerated vectors + negative fixtures
docs/format-spec.md         one format, MAC, canonical rules, pseudocode
```

## Waves

| Wave | Owner | Tasks |
|---|---|---|
| A | Format agent (crypto, entities, usecases encrypt/decrypt, testdata, spec) | T002-T016 |
| A (parallel) | CLI agent (cmd, progress adapter, SDK logger) | T017-T022 |
| B | SDK/session agent (decrypt resolvePrivateKey, pkg/cipher) | T023-T029 |
| C | Integration: docs, changelog, gates | T030-T034 |
