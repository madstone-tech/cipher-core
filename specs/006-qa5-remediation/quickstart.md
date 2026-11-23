# Quickstart: verify the QA verification 5 fixes

## Gates

```sh
task ci
bash tests/external-sdk/run.sh
go test -race ./pkg/cipher/ ./internal/core/usecases/ ./tests/integration/ ./internal/mcp/ ./cmd/ -count=1
```

All pass (2026-11-08, branch `006-qa5-remediation`).

## QA report 5 cases against the built CLI and the MCP server over stdio

Temporary `HOME`, one key in `~/.mdstn/cipher.db` (rollback-journal mode). The `-32600` list holds
two entries: the `"id": null` call and an `"id": true` ping.

| Case | Expected | Observed | Detail |
|---|---|---|---|
| T-1 decrypt -o ~/.mdstn/cipher.db-journal --force | 1 | 1 | created=False; keys=1 |
| T-1 decrypt -o ~/.mdstn/cipher.db-wal --force | 1 | 1 | created=False; keys=1 |
| T-1 decrypt -o ~/.mdstn/CIPHER.DB-JOURNAL --force | 1 | 1 | created=False; keys=1 |
| T-1 decrypt -o ~/.mdstn/cipher.db-mj1234 --force | 1 | 1 | created=False; keys=1 |
| T-1 decrypt ~/.mdstn/cipher.db-journal.mdstn (no options) | 1 | 1 | journal created=False; keys=1 |
| T-1 encrypt -o <db>-wal | 1 | 1 | no side file: True |
| T-1 keys export --output <db>-shm | 1 | 1 | no side file: True |
| T-1 backup -o <db>-journal | 1 | 1 | no side file: True |
| T-2 --db '<db>?_pragma=…' decrypt -o <db> --force | 1 | 1 | keys=1 |
| T-2 --db 'file:<db>?…' decrypt -o <db>-journal | 1 | 1 | created=False |
| T-9 --db other.db, -o <default db>-journal | 1 | 1 | created=False |
| T-5 initialize asks 2025-03-26 | server picks 2025-06-18 |  | 2025-06-18 |
| T-5 `"id": null` delete_key | -32600, not run | [-32600, -32600] | keys=1 |
| T-4 delete_key | -32602 unknown tool | -32602 | keys=1 |
| T-5 lookup_key failure | isError true | True | lookup of nobody@invalid.invalid failed: lookup ke |
| T-6 SIGTERM to idle MCP server | exits < 1 s | 0 | 0.00 s |
| T-7 encrypt x, x.mdstn exists, no TTY | 1, 'already exists' before the prompt | 1 | Error: already exists: output file x.mdstn already exists: file already exists |
| T-10 two backups in one second | 0, 0 and 2 files | 0, 0 | cipher-backup-20261108-135243-2.json, cipher-backup-20261108-135243.json |
| T-8 PEM label | MDSTN WRAPPED X25519 PRIVATE KEY | 0 | -----BEGIN MDSTN WRAPPED X25519 PRIVATE KEY----- |

Not run here: the FAT/exFAT race (S-4) and a TTY Ctrl-C at a password prompt (unit-level code
path only). The hot-journal replay itself was not re-run: no path can create `<db>-journal` any more.

## QA verification 6 cases (U-1 to U-5) against the built CLI

Temporary `HOME`. Gates rerun: `task ci`, external SDK, race tests, spec runner (0 failures).

| Case | Expected exit | Observed | Detail |
|---|---|---|---|
| U-1 `--db ~/link.db` → `~/real/cipher.db`, `-o ~/real/cipher.db-journal` | 1 | 1 | created=False; keys=1 |
| U-1 default DB symlinked to `~/sync`, `decrypt ~/sync/cipher.db-journal.mdstn` (no options) | 1 | 1 | created=False; keys=1 |
| U-1 same setup, `-o ~/sync/notes.txt` (any name) | 1 | 1 | created=False |
| U-2 `--db file:…/cipher%2Edb`, `-o …/cipher.db --force` | 1 | 1 | db unchanged=True; keys=1 |
| U-2 same DSN, `-o …/cipher.db-journal` | 1 | 1 | created=False |
| U-3 DB `k.db`, `-o \u212a.db-journal` (KELVIN SIGN) | 1 | 1 | k.db-journal exists=False; keys=1 |
| U-3 DB `café.db` (NFC), `-o cafe\u0301.db-journal` (NFD) | 1 | 1 | keys=1 |
| U-4 `--db ~/b/k2.db` (hard link of `~/a/k.db`), `-o ~/a/k.db-journal` | 1 | 1 | created=False; keys=1 |
| Control: `-o ~/real/out/plain` (subfolder) | 0 | 0 | created=True |
| Control: default `backup` (`~/.mdstn/backups/`) | 0 | 0 | cipher-backup-20261108-141856.json |
| U-5 MCP `id: 1.5` / `id: 2` | -32600 / result | -32600 / True |  |
