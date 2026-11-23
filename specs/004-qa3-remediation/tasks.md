# Tasks: QA Verification 3 Remediation

**Input**: `specs/004-qa3-remediation/spec.md` (FR-001 to FR-011). Constitution check: format
change (FR-004 name rule) is allowed before the first release tag (Principle III). Public changes
(`ErrAlreadyExists` match, `SessionStore` ttl ≤ 0 = default) ship in v0.3.0 (Principle IV).

**Tests**: REQUIRED; write each test first and confirm it fails.

- [X] T001 [W1] Move `cipher-backup-20261106.json` to `~/.mdstn/backups/`; add `cipher-backup-*.json` to `.gitignore`; `backup` default path in `~/.mdstn/backups/` with a test
- [X] T002 [R-1/R-2] Tests first: header name never affects the output path; `--force`/`Overwrite`/`-o` never replace the input file; then `defaultOutputPath` from the input only and a `FileHandler.SameFile` check
- [X] T003 [R-4] Test first: a 255-byte name decrypts to the default path; fixed-length temp name
- [X] T004 [R-6] Tests first: C1 and bidi names rejected in Go and the spec Python; negative fixture `bidi-filename`; CLI prints the header name quoted
- [X] T005 [R-3] Spec Python rejects signed numbers; Go/Python agreement run
- [X] T006 [R-5] Tests first: malformed MCP calls return errors and the server keeps answering; `ok` checks and per-call `recover`
- [X] T007 [R-7/R-8] Tests first: tampered file leaves no new cache entry; existing output leaves usage unchanged; pending key use committed after Commit
- [X] T008 [R-9] No-replace rename (Linux, macOS), link fallback, check-then-rename fallback; `ErrAlreadyExists` match; CLI hint names `-o` and `--force`
- [X] T009 [R-11] Session TTL from configuration on all paths; test
- [X] T010 [R-10] Docs: CHANGELOG, godoc, help text, spec §Output path and §Header JSON
- [X] T011 Gates (`task ci`, race, external SDK), QA cases on the built binary, record in quickstart.md, commit
