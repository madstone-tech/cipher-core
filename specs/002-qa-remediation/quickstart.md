# Quickstart: verify the single container format

## Gates

```sh
gofumpt -l .            # no output
go vet ./...
go test ./... -count=1
golangci-lint run
```

## Spec pseudocode against the vectors (T015)

The Python blocks of `docs/format-spec.md` §Pseudocode Reference were extracted verbatim, run as one
program, and called with each entry of `internal/testdata/vectors.json`: every `vectors` entry must
decrypt to its plaintext (base64, or length + SHA-256 of `byte[i] = i mod 251`), and every `negative`
entry must raise the exception of its `expect` class (`ParseError` → `parse`, `TamperError` →
`tamper`, `NotARecipient` → `not_a_recipient`, `WrongPassword` → `wrong_password`).

Run on 2026-11-04 with Python 3.15.2 and `cryptography` 50.0.2 (Argon2id from `cryptography`; no
other package). The runner is not committed: extract the ```` ```python ```` blocks between
§Pseudocode Reference and §Governance, `exec` them, and call `decrypt` as the spec's last paragraph
of §Decrypt a file states.

| Array | Name | Method | Expected | Result |
|---|---|---|---|---|
| vectors | `x25519-single` | 2 | ok | pass |
| vectors | `x25519-single-bundle` | 2 | ok | pass |
| vectors | `x25519-multi` | 2 | ok | pass |
| vectors | `passphrase` | 3 | ok | pass |
| vectors | `sharedkey` | 5 | ok | pass |
| vectors | `x25519-single-chunked` | 2 | ok | pass |
| vectors | `x25519-single-bundle-chunked` | 2 | ok | pass |
| vectors | `x25519-multi-chunked` | 2 | ok | pass |
| vectors | `passphrase-chunked` | 3 | ok | pass |
| vectors | `sharedkey-chunked` | 5 | ok | pass |
| vectors | `x25519-multi-16` | 2 | ok | pass |
| vectors | `passphrase-len-0` | 3 | ok | pass |
| vectors | `x25519-single-len-0` | 2 | ok | pass |
| vectors | `passphrase-len-1` | 3 | ok | pass |
| vectors | `x25519-single-len-1` | 2 | ok | pass |
| vectors | `passphrase-len-65535` | 3 | ok | pass |
| vectors | `x25519-single-len-65535` | 2 | ok | pass |
| vectors | `passphrase-len-65536` | 3 | ok | pass |
| vectors | `x25519-single-len-65536` | 2 | ok | pass |
| vectors | `passphrase-len-65537` | 3 | ok | pass |
| vectors | `x25519-single-len-65537` | 2 | ok | pass |
| vectors | `passphrase-len-131072` | 3 | ok | pass |
| vectors | `x25519-single-len-131072` | 2 | ok | pass |
| negative | `truncated-at-boundary` | 3 | tamper | pass |
| negative | `frame-after-final` | 3 | tamper | pass |
| negative | `frame-0-removed` | 3 | tamper | pass |
| negative | `empty-final-frame` | 3 | tamper | pass |
| negative | `two-cek` | 2 | tamper | pass |
| negative | `crlf-in-base64` | 3 | parse | pass |
| negative | `noncanonical-base64-padding` | 3 | parse | pass |
| negative | `version-0x01` | 3 | parse | pass |
| negative | `version-0x02` | 3 | parse | pass |
| negative | `wrong-password` | 3 | wrong_password | pass |
| negative | `not-a-recipient` | 2 | not_a_recipient | pass |

0 failures

## QA tamper table against the built CLI (T033)

Run on 2026-11-05 on branch `002-qa-remediation`. Password file of 20 × 64 KiB (an exact multiple
of the chunk size), plus the QA cases N2-N7, V2-2, V2-7. The unchanged file round-trips
byte-identical.

| Case | Expected exit | Observed exit | Output file / detail |
|---|---|---|---|
| swap frames 0 and 1 | 2 | 2 | none |
| repeat frame 0 | 2 | 2 | none |
| remove frame 5 | 2 | 2 | none |
| remove frame 0 | 2 | 2 | none |
| truncate after 3 frames + terminator | 2 | 2 | none |
| truncate, no terminator | 2 | 2 | none |
| bytes after terminator | 2 | 2 | none |
| base nonce bit flip | 2 | 2 | none |
| bit flip in chunk 10 | 2 | 2 | none |
| forged length 0xFFFFFFF0 | 2 | 2 | none |
| forged length 8 | 2 | 2 | none |
| header MAC bit flip (password file) | 4 | 4 | none |
| version 0x03 → 0x01 | 1 | 1 | none |
| unchanged | 0 | 0 | present |
| wrong password | 4 | 4 | none |
| N2/N4/N5 keys create --json | 0 | 0 | valid JSON, 24-word phrase, secret fields: none |
| N3 keys create, no TTY, no --yes | 1 | 1 | keys after: [] |
| V2-2 recipient key with bit 255 set | 1 | 1 | none |
| N7 --recipient "" | 1 | 1 | none |
| N4 encrypt --json | 0 | 0 | valid JSON |
| V2-7 decrypt --json | 0 | 0 | method=x25519-hkdf-aes256, version=3 |
| N6 password method label | 0 | 0 | passphrase-aes256 |

N1 and N8 are covered by `pkg/cipher/passphrase_check_test.go` (`TestSuppliedPassphraseIsAlwaysChecked`, `TestConcurrentCallsKeepPassphrasesApart` under `-race`).
Both fail on the code before the fix: the wrong passphrase decrypted after an unlock, and the race
detector reported a data race.
