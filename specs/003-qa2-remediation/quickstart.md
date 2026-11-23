# Quickstart: verify the QA verification 2 fixes

## Gates

```sh
task ci
bash tests/external-sdk/run.sh
go test -race ./pkg/cipher/ ./internal/core/usecases/ ./tests/integration/ -count=1
```

All pass (2026-11-05, branch `003-qa2-remediation`).

## QA attack cases against the built CLI (T016)

The Q1 files were built outside the Cipher encoder (which now rejects such names), following the
spec: valid header MAC and body, with a hostile `original_filename`. Each decrypt ran from a
separate working directory without `-o`.

| Case | Expected exit | Observed exit | Detail |
|---|---|---|---|
| Q1 forged original_filename: relative ../victim/target.txt | 1 | 1 | target: ORIGINAL |
| Q1 forged original_filename: absolute path | 1 | 1 | target: ORIGINAL |
| Q1 forged original_filename: name with ':' | 1 | 1 | target: ORIGINAL |
| Q1 safe name, no -o: output next to input | 0 | 0 | inbox/note.txt=True, cwd/note.txt=False |
| Q1 default path exists | 1 | 1 | inbox/note.txt=KEEP; partials=0 |
| Q1 default path exists, --force | 0 | 0 | inbox/note.txt=v1 |
| explicit -o onto an existing file | 0 | 0 | replaced (user choice) |
| Q2 password encrypt, text + JSON output | 0 | 0 | sha256(password) in output: False; JSON fingerprint='' |
| Q5 NaN header fixture | 1 | 1 | none |

## Go and the spec Python agree on header rules (T012)

25 headers (NaN, Infinity, fraction, `1.0`, exponent, negative, 2^53, a 400-digit integer, a lone
surrogate, nesting 9 and 20000, an unknown float member, 8 unsafe names, and 5 valid controls):
Go `DecodeHeader` and the spec `parse_header` give the same result for 25 of 25.

## Spec pseudocode against every vector and negative fixture

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
| negative | `bad-filename` | 3 | parse | pass |
| negative | `nan-in-header` | 3 | parse | pass |

0 failures


## Production path (Q7)

`tests/integration/vectors_production_test.go` runs all 23 vectors and 13 negative fixtures through
`DecryptFile.DecryptStream`: 36 of 36 pass. Method-5 vectors are checked to be refused by the
usecase (only the managing client holds the policy key).
