# Tasks: QA Verification 4 Remediation

**Input**: `specs/005-qa4-remediation/spec.md`. Constitution check: no new dependency
(Principle V). The name rule (FR-008) changes before the first release tag (Principle III). Public
changes (`EncryptInput.Overwrite`, MCP tool set) ship in v0.3.0 (Principle IV).

**Tests**: REQUIRED; write each test first and confirm it fails.

- [X] T001 [S-1] Test first: `export_key` returns the export JSON and writes no file; remove `output`
- [X] T002 [S-3] Remove the `create_key` MCP tool; update the tool-set test
- [X] T003 [S-8/S-2] Tests first: `internal/mcp.Serve` over a pipe (`initialize`, notification, bad line, array, `tools/list`, `tools/call` JSON result, `isError`, unknown tool, oversized line); implement; `cmd/mcp.go` calls it; `lookup_key` requires `email`
- [X] T004 [S-5] Tests first: encrypt default path never replaces; `--force`/`Overwrite`; `-o` = input refused; implement in the usecase, CLI, SDK
- [X] T005 [S-6] Tests first: two backups in a row keep both; mode fixes; implement
- [X] T006 [S-4] Test first: placeholder fallback refuses an existing name and publishes a free one; implement
- [X] T007 [S-7] Test first: `-o <dir>` fails before work (decrypt and encrypt); implement
- [X] T008 [S-9] Tests first (Go and spec Python): Cf/Zl/Zp list; implement in `entities` and the spec
- [X] T009 [S-10/S-11] Docs: godoc, comments, spec, CHANGELOG, README, AGENTS
- [X] T010 Gates, QA cases on the built binary (MCP over stdio included), quickstart.md, commit
