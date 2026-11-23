# Feature Specification: QA Verification 4 Remediation

**Feature Branch**: `005-qa4-remediation` | **Created**: 2026-11-06 | **Status**: Clarified

**Input**: "Address `cipher-core-review-2026-11-04/cipher-core-verification-4.md` (S-1 to S-11).
I am OK with dropping decryption of v1 files."

## Clarifications

### Session 2026-11-06

- Q4 (v1 files): final. v1 decryption stays dropped.
- S-1: MCP `export_key` returns the export in the tool result. The `output` argument is removed.
- S-8: a small hand-written MCP stdio protocol layer. No new dependency.
- S-3: the MCP `create_key` tool is removed.
- S-6: backups are named `cipher-backup-YYYYMMDD-HHMMSS.json` and never replace a file.

## Requirements

- **FR-001 (S-1)**: No MCP tool writes to a path that the caller chooses, except `encrypt_file` and
  `decrypt_file`, which never replace a file (FR-004).
- **FR-002 (S-3)**: MCP has no `create_key` tool. In MCP mode, nothing but protocol messages is
  written to stdout.
- **FR-003 (S-8, S-2)**: The MCP server answers `initialize` (protocol version, `tools`
  capability, server info) and `ping`, never answers a notification (no `id`), reads one message
  per line up to 4 MiB, answers an invalid line with `-32700`/`-32600` and keeps serving, returns
  tool results as JSON text, and reports tool failures with `isError: true`. Unknown tools and
  methods give JSON-RPC errors.
- **FR-004 (S-5)**: `encrypt` never replaces a file at its default path (`<input>.mdstn`) unless
  `--force`/`Overwrite`, and never writes over its own input. MCP `encrypt_file` never replaces.
- **FR-005 (S-6)**: `backup` names files with date and time, creates them exclusively (with or
  without `-o`), and keeps `~/.mdstn`, `~/.mdstn/backups` at 0700 and the key database at 0600.
- **FR-006 (S-4)**: Where no atomic no-replace rename or hard link exists, the publish reserves the
  final name with `O_CREAT|O_EXCL` and then renames over that placeholder.
- **FR-007 (S-7)**: An output path that is a directory is a usage error before any decryption or
  encryption work.
- **FR-008 (S-9)**: A safe base name also excludes the invisible format, line, and paragraph
  separator characters (Unicode Cf, Zl, Zp), as an explicit code-point list in the spec, so that
  Go and the spec Python agree regardless of their Unicode table versions.
- **FR-009 (S-10, S-11)**: Documentation matches the code. §Output path documents the by-path
  sameness check (S-11).

## Success Criteria

- **SC-001**: No MCP call can replace a file. The QA stdio sequence (`initialize`, bad line,
  `tools/list`) gets 3 correct answers.
- **SC-002**: A second `backup` and a second `encrypt` never destroy the first output.
- **SC-003**: `task ci` passes.
