# Quickstart: verify the QA verification 3 fixes

## Gates

```sh
task ci
bash tests/external-sdk/run.sh
go test -race ./pkg/cipher/ ./internal/core/usecases/ ./tests/integration/ ./internal/mcp/ -count=1
```

All pass (2026-11-06, branch `004-qa3-remediation`). The spec pseudocode runs all vectors and negative
fixtures (14 negative fixtures, now with `bidi-filename`): 0 failures.
Go and the spec Python agree on 40 of 40 header cases (R-3 `-0`, `+1`, `01`, `1E2`; R-6 C1 and bidi names).

## QA report 3 cases against the built CLI

Hostile files were built from the spec key schedule (valid header MAC and body), so the encoder
checks do not apply. `HOME` was a temporary directory.

| Case | Expected exit | Observed exit | Detail |
|---|---|---|---|
| R-1 header name `.zshenv`, no -o | 0 | 0 | .zshenv created: False; wrote invoice.pdf: True; shows ['Sender\'s file name: ".zshenv"'] |
| R-2 header name = input, --force | 0 | 0 | input unchanged: True; output self: b'PLAIN' |
| R-2 `-o` = the input, --force | 1 | 1 | input unchanged: True |
| R-1+R-2 header `.zshrc`, --force in $HOME | 0 | 0 | ~/.zshrc: ORIG; output: x |
| R-4 250-byte input name, no -o | 0 | 0 | output 244-byte name exists: True |
| R-6 header name with U+202E | 1 | 1 | parse error |
| R-9/R-10 default path exists | 1 | 1 | hint names -o and --force: True; kept: KEEP |
| W1 `backup` without -o | 0 | 0 | in ~/.mdstn/backups: ['cipher-backup-20261106.json']; in cwd: [] |
| R-5 MCP: `{}`, `file_path=42`, then tools/list | 0 (alive) | 0 | answers: {1: 'error', 2: 'error', 3: 'error', 4: 'result'}; panic in stderr: False |

The no-replace rename test (`TestRenameNoReplace`) ran on APFS (macOS) and used `renamex_np`.
[INFERENCE] The Linux `renameat2` path compiles (`GOOS=linux go build`) and runs in CI on Linux;
it was not executed locally.
