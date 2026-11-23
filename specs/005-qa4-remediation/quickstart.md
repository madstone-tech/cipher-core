# Quickstart: verify the QA verification 4 fixes

## Gates

```sh
task ci
bash tests/external-sdk/run.sh
go test -race ./pkg/cipher/ ./internal/core/usecases/ ./tests/integration/ ./internal/mcp/ ./cmd/ -count=1
```

All pass (2026-11-06, branch `005-qa4-remediation`). Spec pseudocode: 0 failures on all vectors and
14 negative fixtures. Go and the spec Python agree on 54 of 54 header cases, including 13 invisible
characters (S-9). `TestInvisibleRangesMatchUnicode` checks that the frozen list equals Cf ∪ Zl ∪ Zp
of the Go Unicode tables (17.0.0); Python 3.15 (`unicodedata` 17.0.0) gives the same 172 code points.

## QA report 4 cases against the built CLI and the MCP server over stdio

| Case | Expected | Observed | Detail |
|---|---|---|---|
| S-8 initialize | result | result | protocolVersion=2025-06-18 |
| S-8 notification gets no reply | 8 replies (8 requests + 1 notification) | 8 replies | ids: 1,2,3,None,None,4,5,6 |
| S-1 export_key output=~/.zshrc | JSON in result, no write | isError=False | ~/.zshrc: ORIG; result keys: ['fingerprint', 'id', 'public_key', 'type'] |
| S-1 export_key output=key DB | no write | no write | still `SQLite format 3` with 1 key. (Opening the DB alone changes its bytes; an export after the open changes 0 bytes.) |
| S-2 `{not json`, `[1,2]` | -32700, -32600, keep serving | [-32700, -32600] | tools/list answered after: True |
| S-3 create_key | -32602 unknown tool | -32602 | non-JSON stdout lines: 0 |
| S-8 lookup_key {} | isError result | isError=True | invalid input: argument "email" must be a non-empty string |
| tools/list | no create_key | absent | encrypt_file,decrypt_file,list_keys,delete_key,export_key,get_status,lookup_key,import_key |
| S-6 backup, delete key, backup | 2 files, first keeps the key | 0,0 | files=2 key counts=[1, 0] |
| S-6 modes | 0o700 / 0o700 / 0o600 | - | ~/.mdstn=0o700 backups=0o700 c.db=0o600 |
| S-6 backup -o onto an existing backup | exit 1, file kept | 1 | key count still 1 |
| S-5 encrypt x twice | 0 then 1, first kept | 0,1 | x.mdstn unchanged=True; hint names --force=True |
| S-5 encrypt x --force | 0 | 0 | replaced |
| S-5 encrypt x -o x | 1 | 1 | input unchanged=True |
| S-7 -o <directory> (encrypt, decrypt) | 1, 1 | 1, 1 | Error: invalid input: output path outdir is a directory |
