# Data Model: CKD hosted-directory client support

Phase 1 output. Entities, fields, validation, state transitions touched by this feature.
Container format entities (v0x03) are intentionally absent — untouched (Constitution III).

## Entities

### DirectoryToken (not persisted by the client)

| Field | Type | Validation | Notes |
|---|---|---|---|
| Value | string | ≥ 32 bytes when server-issued; non-empty | Hex from the verify confirm page |
| Email | string | lowercase/trim before use | The single email the token licenses |

Rules: flag `--kd-token` overrides env `KD_TOKEN`; empty after both → fail before any network
send (FR-001). Never logged, never in JSON output (FR-012).

### PublisherPublicKey (selected from the key store; existing `IdentityKey`)

| Field used | Notes |
|---|---|
| PublicKey | base64-std in publish body (existing behavior) |
| Fingerprint | hex; sent in a rotation/tombstone publish body |
| Type | `x25519` — the only publishable type (existing filter at `cmd/keys.go:440`) |

### PublishedBinding (server-held; client only receives/responds)

State machine (server-owned; the client must understand the responses, not the transitions):

```
            publish (token)
   empty ────────────────────▶ pinned
   pinned ── publish (token + current fingerprint + poc) ──▶ pinned (rotated)
   pinned ── publish (token only) ──▶ 409 current_fingerprint_required (state unchanged)
   pinned ── unpublish (token) ──▶ tombstone (tombstone_until = +30d)
   tombstone ── publish (token + tombstone fingerprint + poc) ──▶ pinned
   tombstone (≥30d) ── publish (token) ──▶ pinned (fresh)
```

Client contract per response: `200` → report success (+ `rotated:true` when present);
`409 current_fingerprint_required` → show `current_fingerprint`, conflict exit; `409
fingerprint_mismatch` → relay verbatim; `403 possession_proof_invalid` → relay verbatim;
`401` → auth error; `429` → rate-limit error.

CLI exit codes (defined in `cmd/exit.go`, T002; normative table in `docs/format-spec.md`
§Governance item 5): `401`/`403` → `ExitAuthFailed` (2); `409` (both kinds) and possession
rejections → `ExitConflict` (5); signature/key-id/missing-header failures → `ExitIntegrity`
(6); `429`, network, and generic server failures → `ExitError` (1).

### ServiceSigningKey (pinned in client)

| Field | Value | Source |
|---|---|---|
| KeyID | `kd-2026-11` | `ckd-server/docs/ckd-service-key.md` |
| PublicKey | base64-std 32 bytes `gqd2RnaBd5ZShK1AIVk5KGMzIemiQ+K2OPF3CLIASh8=` | same |
| Covered content | `email_hash + "\n" + raw_body_bytes` | server contract |

Rules: signature header `X-Mdstn-Kd-Signature` (base64-std); key id header
`X-Mdstn-Kd-Keyid`; compare ids with `crypto/subtle`; missing either header → integrity
failure; unrecognized id → surfaced pin conflict, response rejected (FR-005/FR-006).

### CKDCacheEntry (extended; client-held TOFU cache)

| Field | Type | Change | Notes |
|---|---|---|---|
| Email | string | unchanged | lowercase/trim key |
| **KeyType** | string | **added** | default `x25519`; decode from response; unknown → surfaced, not cached |
| PublicKey | []byte | unchanged | raw decoded key bytes |
| Fingerprint | string | unchanged | hex |
| FirstSeen / LastSeen | int64 | unchanged | unix seconds |

Identity: `(email, key_type)` — two key types for one recipient never overwrite each other (spec Story 4, acceptance 1).

### CKDLookupResponse (wire shape; frozen + additive)

```json
{"email":"…","public_key":"<base64-std>","fingerprint":"<hex>","created_at":<int64-unix>,"key_type":"x25519"}
```

`key_type` optional (absent ⇒ `x25519`); decode must tolerate its absence (spec Story 4,
acceptance 3). Byte-exact fixture: `internal/testdata/ckd/lookup.json` (copy of
ckd-server `test/contract/fixtures/lookup.json`, hash `ff8d9819…`).

## Schema migration (SQLite `ckd_cache`)

Additive, backward compatible:

1. Create `ckd_cache_new (email TEXT, key_type TEXT NOT NULL DEFAULT 'x25519', public_key BLOB
   NOT NULL, fingerprint TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT
   NULL, PRIMARY KEY (email, key_type))`.
2. Copy old rows: `INSERT … SELECT email,'x25519',public_key,fingerprint,first_seen,last_seen
   FROM ckd_cache` (dedupe on conflict, keep lowest first_seen).
3. Drop `ckd_cache`; rename `ckd_cache_new` → `ckd_cache`; recreate the fingerprint index.

Migration failure → warn and operate cacheless (existing posture: lookup works, caching
disabled — matches `NewClient` nil-cache semantics).
