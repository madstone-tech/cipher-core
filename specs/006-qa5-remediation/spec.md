# Feature Specification: QA Verification 5 Remediation

**Feature Branch**: `006-qa5-remediation` | **Created**: 2026-11-08 | **Status**: Implemented

**Input**: "Look at `cipher-core-verification-5.md` for the latest feedback" (T-1 to T-10).

## Clarifications

### Session 2026-11-08

- T-4: the MCP `delete_key` tool is removed. Key deletion stays the CLI `keys delete`.

## Requirements

- **FR-001 (T-1)**: No output may create or replace a key-database file: the database or any
  `<db>-…` name in its folder, any case, whether or not the file exists.
- **FR-002 (T-2)**: A database DSN (`file:`, `?query`) is reduced to its file path for FR-001 and
  for the 0600 mode.
- **FR-003 (T-4)**: MCP has no `delete_key` tool.
- **FR-004 (T-5)**: A request with `"id": null` or a non-scalar id gets `-32600` and does not run.
  The server offers only protocol versions it fully supports (2025-06-18, 2024-11-05). A failed
  `lookup_key` is `isError`.
- **FR-005 (T-6)**: SIGTERM stops an idle MCP server. A cancelled command publishes nothing. A
  password prompt ends on SIGINT and restores the terminal.
- **FR-006 (T-3)**: The SDK `New` fails instead of falling back to `./cipher.db`.
- **FR-007 (T-7)**: An existing default output fails before any lookup, prompt, or KDF. Key usage
  is counted after the publish on every path.
- **FR-008 (T-8)**: The PEM export label says the key is wrapped.
- **FR-009 (T-9)**: One shared output check. The CLI always protects the default database too.
- **FR-010 (T-10)**: A second default backup in one second gets a `-N` name.

## Amendment: QA verification 6 (U-1 to U-5)

Session 2026-11-08 clarification: the guard refuses EVERY output in a database folder, not
only `<db>`/`<db>-…` names (user choice over extended name matching).

- **FR-011 (U-1, U-3, U-4)**: Protected folders are the configured folder, the resolved
  (symlink) folder, and a folder that holds a hard link to the database.
- **FR-012 (U-2)**: `file:` DSNs are decoded like the driver (`%XX`, `//localhost`, `#fragment`).
- **FR-013 (U-5)**: MCP refuses a non-integer number id with `-32600`.

## Success Criteria

- **SC-001**: No CLI, SDK, or MCP path can write `<db>-journal`; the QA hot-journal attack fails.
- **SC-002**: `task ci` passes.
