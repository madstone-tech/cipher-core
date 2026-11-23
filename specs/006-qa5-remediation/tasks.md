# Tasks: QA Verification 5 Remediation

**Input**: `specs/006-qa5-remediation/spec.md`. Constitution: no format change, no new
dependency. Public changes (`ProtectKeyStore` replaces `ProtectPaths`, `CheckOutputPath`,
`CheckOutput`, `New` error, MCP tool set) ship in v0.3.0.

- [X] T001 [T-1/T-2/T-9] Name-based key-store guard (`usecases.CheckOutputPath`, `KeyStorePath`, `ProtectKeyStore`); CLI protects `--db` and the default DB; tests for non-existent side files, case, DSN, derived path
- [X] T002 [T-4] Remove MCP `delete_key`; test
- [X] T003 [T-5] `"id": null`/non-scalar ids refused; drop 2025-03-26; `lookup_key` failure is `isError`; tests
- [X] T004 [T-6] MCP reader goroutine with cancellation; `commitOutput` checks the context; cancellable prompt; tests
- [X] T005 [T-3] SDK `New` error without a home directory; test
- [X] T006 [T-7] `EncryptFile.CheckOutput` and early existing-file checks (encrypt, decrypt); stream key usage after commit; CLI test
- [X] T007 [T-8] Wrapped-key PEM label; test
- [X] T008 [T-10] Numbered default backup names; backup guard; tests
- [X] T009 Docs: CHANGELOG, README, AGENTS, spec §Output path, help texts, godoc
- [X] T010 Gates and QA cases on the built binary; quickstart.md; commit
- [X] T011 [U-1/U-3/U-4] Folder guard (`isKeyStoreDir`, `FileHandler.ResolvePath`, `DirHoldsLink`); tests DB in own folder (`keyDB`); symlink, hard-link, KELVIN SIGN tests
- [X] T012 [U-2] `KeyStorePath` decodes `file:` URIs; table test
- [X] T013 [U-5] Integer-only MCP ids; test
- [X] T014 Docs, gates, QA cases on the built binary; commit
