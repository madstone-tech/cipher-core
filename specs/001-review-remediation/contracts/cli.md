# Contract: CLI

## Exit codes (`docs/format-spec.md` §Governance item 5)

| Code | Meaning | Error |
|---|---|---|
| 0 | success | — |
| 1 | parse, usage, I/O, invalid key, unsupported version | any other error |
| 2 | tamper or header authentication failure | `ErrHeaderAuthFailed` |
| 3 | not a recipient | `ErrNotARecipient` |
| 4 | wrong file password (or damaged password file) | `ErrWrongPassword` |

All commands use one mapping, `cmd.ExitCode(err)`. No command calls `os.Exit` itself, except
`main`.

## `encrypt <file>`

| Flag | Change | Behavior |
|---|---|---|
| `--recipient <email\|id>` | unchanged, repeatable | CKD lookup or local key |
| `--recipient-key <b64\|path>` | new, repeatable | raw 32-byte X25519 public key, validated before output |
| `--for <email>` | unchanged | one CKD recipient |
| `--password <pw>` | unchanged | file password |
| `--password-file <path\|->` | new | file password from a file or stdin, one trailing newline removed |
| `--key-passphrase-file <path\|->` | new | passphrase for the default key (encrypt for self) |
| `-o, --output` | unchanged | output path |

Rules:

- With any recipient flag, the command does not prompt for a file password.
- `--password` and `--password-file` together: usage error.
- Recipient flags together with a password flag: usage error.
- Without any of these flags, the command prompts for a file password (existing behavior).
  `--key-passphrase-file` selects "encrypt for yourself" with the default key. The help text
  says both.

## `decrypt <file>`

New: `--password-file <path|->`, `--key-passphrase-file <path|->`. Without a terminal and without
the needed secret, the command fails with exit 1 and the message names the missing flag.

## `keys create`

New: `--key-passphrase-file <path|->`. Priority: `--key-passphrase` > `--key-passphrase-file` >
`MDSTN_KEY_PASSPHRASE` > prompt.

## Signals

SIGINT and SIGTERM cancel the command context. A cancelled encryption or decryption leaves no file
at the output path and exits with code 1.
