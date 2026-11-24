# Phase 0 Research: CKD hosted-directory client support

All Technical-Context and spec unknowns resolved. No `NEEDS CLARIFICATION` remains.

## R1. Publish authentication mechanism

**Decision**: Bearer `kd_token` in `Authorization` header; token supplied via `--kd-token` flag
(env `KD_TOKEN` as fallback). Flag wins over env. Token never persisted by the client.

**Rationale**: the ckd-server contract (`specs/001-keys-directory/contracts/api.md`) rejects
unauthenticated publishes with `401 {"error":"unauthorized"}`; PRD §4 defines the token flow.
Env fallback follows the existing `CIPHER_SERVER_URL` pattern in `cmd/keys.go:428`.

**Alternatives considered**:
- Session auth — rejected: that is the hosted-app model; no accounts exist in the directory flow.
- Storing the token in the key DB — rejected: a stored secret invites leakage through exports/
  logs; the user keeps the token (shown once by the verify page).

## R2. Rotation contract and proof-of-possession kind

**Decision**: publish body gains `fingerprint` (hex of the published key) and
`poc: {"type":"fingerprint_token"}`. On `409 current_fingerprint_required`, the CLI prints the
server's `current_fingerprint` with corrective guidance and exits with a conflict-class code. No
automatic retry. `409 fingerprint_mismatch` and `403 possession_proof_invalid` relay verbatim.

**Rationale**: X25519 keys cannot sign the `/mdstn-kd/rotate-v1/…` challenge, so PRD §5's
fallback (fingerprint + current token as second factor) is the only v1-viable poc; the server
contract names it `"fingerprint_token"` (publish.json fixture). Tombstone re-bind uses the same
body shape with the tombstone fingerprint.

**Alternatives considered**:
- Interactive challenge signing with a separate ed25519 identity — deferred (server v2); adds
  identity concepts the key store does not have today.
- Silent auto-retry with server-provided fingerprint — rejected: builds a poc from server data
  without user intent; masks the "someone else holds the binding" edge case (spec edge 1).

## R3. Response signature verification

**Decision**: verify `X-Mdstn-Kd-Signature` (base64-std ed25519) over
`email_hash + "\n" + raw_body_bytes` against the pinned service public key
`gqd2RnaBd5ZShK1AIVk5KGMzIemiQ+K2OPF3CLIASh8=`, key id `kd-2026-11`
(`ckd-server/docs/ckd-service-key.md`, verified live 2026-11-24). Key id from
`X-Mdstn-Kd-Keyid` compared constant-time against the pinned id; an unrecognized id is surfaced
(pin-conflict behavior), the response is NOT accepted. Missing headers → integrity failure.

**Rationale**: PRD §3 pairs signing with TOFU; the key id header is the client-visible rotation
signal (ckd-service-key.md §Rotation). Reading the body once as raw bytes before decode keeps
the signature input exact — `fetchKey` already reads the full body before unmarshal
(`internal/adapters/ckd/client.go:133`).

**Alternatives considered**:
- Accept-unsigned fallback — rejected: spec SC-003 requires 100% verification of accepted
  responses; an unsigned fallback reopens the poisoning window.
- Verify only on first sight (TOFU the signature) — rejected: a per-response verify is ~50 µs;
  anything weaker allows equivocation.
- Per-email-hash key selection — not needed: one service key; if multi-key arrives, the key-id
  map extends (documented in contracts/ckd-wire.md).

## R4. key_type handling and TOFU cache schema

**Decision**: decode `key_type` (default `"x25519"` when absent). Unknown value →
error surfaced, nothing cached. `CKDCacheEntry` gains `KeyType string`. Cache uniqueness becomes
`(email, key_type)`; SQLite migration is additive: `ALTER TABLE ckd_cache ADD COLUMN key_type
TEXT NOT NULL DEFAULT 'x25519'` + new unique index on `(email, key_type)` (drop old
email-PK-backed unique constraint by table rebuild: create `_ckd_cache_new`, copy, swap). Rows
from old caches keep working (default type fills in).

**Rationale**: the protocol doc's forward-compatibility note keys TOFU on `(email_hash,
key_type)`. Doing it now avoids a later breaking interface change on `CKDCacheRepository`
(Constitution IV wants the widening in the same minor bump that introduces the need). `Get`
signature widens to take `keyType`, or the entry carries it — resolved in data-model.md; the
interface change ships in v0.4.0 with justification.

**Alternatives considered**:
- Ignore key_type today (client treats all keys as x25519) — rejected: FR-007/FR-008 would be
  unmet and a later cache migration would break external `CKDCacheRepository` implementers.
- Generic typed cache (arbitrary metadata map) — rejected: over-abstraction for one known
  attribute; boring design preferred per repo conventions.

## R5. Wire fixture source of truth

**Decision**: copy `ckd-server/test/contract/fixtures/lookup.json` byte-for-byte into
`internal/testdata/ckd/lookup.json`; the contract test asserts exact field round-trip against
it. The doc-draft hash in CONTEXT-LIFT-FROM.md (`5891b5…`) is superseded by the confirmed hash
`ff8d9819…` (CONTEXT-LIFT-FROM.md note, user-confirmed 2026-11-24). The fixture is normative
testdata: never hand-edited, per AGENTS.md fixture discipline.

**Rationale**: PRD §12 mandates the shared fixture in both repos. Copying (not vendoring at
build time) keeps the public module self-contained and its testdata canonical.

**Alternatives considered**:
- Git submodule on ckd-server — rejected: ckd-server is private; a public module cannot
  submodule-pin it, and CI would fail on a public checkout.
- Generate fixture locally — rejected: divergence risk; the server's bytes are the contract.

## R6. Default server URL & backward compatibility

**Decision**: `CIPHER_SERVER_URL`/`--server-url` still override; when absent, publish/unpublish
default to `https://keys.mdstn.dev` instead of erroring. Lookup path unchanged
(`NewClient` already pins `https://keys.mdstn.dev`, `internal/adapters/ckd/client.go:33`).

**Rationale**: spec FR-003 (one command, no other config) and spec Story 1 acceptance 1.
Self-hosted operators keep the override, so the "per-instance CKD" mode is not removed.

**Alternatives considered**:
- Require explicit `--server-url` always — rejected: breaks the PRD definition-of-done
  round trip UX.
- New flag `--kd-server` — rejected: two flags for one concept; reuse the existing one.

## R7. Error classes and exit codes

**Decision**: map server responses to the existing CLI error-class plumbing: `401` →
authentication error; `409` (both kinds) → conflict error with server body relayed; `403` →
authorization (possession) error; signature/kid failures on lookup → integrity error, distinct
from network errors. Exit codes follow `cmd/exit.go` class conventions; no new class invented
unless `exit.go` lacks a conflict/integrity mapping — checked during tasks; if absent, add the
minimal mapping in `cmd/exit.go`.

**Rationale**: Constitution V requires error-class separation end to end.

**Alternatives considered**: single generic "server error" — rejected by FR-011.

## R8. Protocol document updates

**Decision**: extend `docs/ckd-protocol.md` with (a) the signed-response header + covered
content + service key id/public key, (b) publish rotation request fields and the conflict
response matrix, (c) `key_type` client behavior. Additive sections only; existing wire format
text untouched. Not a format-governance event (container spec untouched).

**Rationale**: FR-010 and PRD §3 ("Key published in the repo and in docs/ckd-protocol.md").

**Alternatives considered**: separate document — rejected: the protocol doc is the normative
single source; splitting invites drift.
