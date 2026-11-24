# Contract: CKD wire & CLI surface (007-ckd-hosted-directory)

The wire contract with keys.mdstn.dev, plus the CLI surface changes. Normative
references: `docs/ckd-protocol.md` (public), ckd-server
`specs/001-keys-directory/contracts/api.md` (server). Byte-exact fixture:
`internal/testdata/ckd/lookup.json`.

## C1. Publish request/response (additive)

`POST /api/v1/ckd/publish`, `Authorization: Bearer <kd_token>`, `Content-Type: application/json`.

Fresh binding body:

```json
{"email":"alice@example.com","public_key":"<base64-std>"}
```

Rotation / tombstone re-bind body (superset, additive):

```json
{"email":"alice@example.com","public_key":"<base64-std>",
 "fingerprint":"<hex of published key>","poc":{"type":"fingerprint_token"}}
```

Success `200 {"status":"published","email":"…","email_hash":"…"}` (rotation adds
`"rotated":true`).

Failure codes the CLI must distinguish:
- `401 {"error":"unauthorized"}` → authentication class
- `409 {"error":"current_fingerprint_required","current_fingerprint":"<hex>"}` → conflict
  class; CLI surfaces `current_fingerprint` with guidance, NO auto-retry
- `409 {"error":"fingerprint_mismatch"}` → conflict class, relayed verbatim
- `403 {"error":"possession_proof_invalid"}` → authorization class, relayed verbatim
- `429 {"error":"rate_limited"}` → rate-limit class

## C2. Unpublish request/response

`DELETE /api/v1/ckd/unpublish`, Bearer token, body `{"email":"…"}` →
`200 {"status":"unpublished"}` (idempotent). Same 401/429 semantics.

## C3. Signed lookup response

`GET /.well-known/mdstn-cipher/{email_hash}`:

- Headers: `X-Mdstn-Kd-Signature: <base64-std ed25519>`, `X-Mdstn-Kd-Keyid: kd-2026-11`.
- Covered content: `email_hash + "\n" + raw_body_bytes`.
- Pinned service public key (base64-std, 32 bytes):
  `gqd2RnaBd5ZShK1AIVk5KGMzIemiQ+K2OPF3CLIASh8=` (ed25519 seed‖pub stored server-side; the
  pinned value is the PUBLIC half).
- Body: frozen JSON shape + optional `key_type` (absent ⇒ `x25519`).

Client rules:
1. Read raw body once; verify signature before decode acceptance.
2. Key id mismatch vs. pinned (constant-time compare) → surface pin conflict; reject response.
3. Missing headers → integrity failure.
4. Unknown `key_type` → surfaced, response rejected (not cached). Absent/known `key_type` →
   proceed with that type.
5. No cache write before verification passes (FR-005).

## C4. CLI surface

```
mdstn-cipher keys publish --email <email> [--kd-token <token>] [--server-url <url>]
mdstn-cipher keys unpublish --email <email> [--kd-token <token>] [--server-url <url>]
```

- Token precedence: `--kd-token` > `KD_TOKEN` env > error with remediation text (before any
  network call).
- `--server-url` / `CIPHER_SERVER_URL` still override; default is now
  `https://keys.mdstn.dev` (was: hard error when unset).
- Exit codes: authentication/conflict/integrity failures map to the existing error-class
  plumbing in `cmd/exit.go`; conflict text includes the server body.
- Output discipline: token and key material never appear in stdout/logs/errors.

## C5. In-module interfaces changed (constitutions I/IV)

- `usecases.CKDCacheEntry` gains `KeyType string`.
- `usecases.CKDCacheRepository` methods become key-type aware (Get/Delete take the type;
  effective identity `(email, key_type)`).
- Re-export unchanged in `pkg/cipherports` (aliasing only); justification recorded in
  plan.md Constitution Check; ships in v0.4.0.
- `ckd.Client` gains: response signature verification, key_type decode; publish-side stays in
  cmd (transport-only), matching the current layering.

## C6. Cross-repo fixture test

- `internal/testdata/ckd/lookup.json` == ckd-server
  `test/contract/fixtures/lookup.json`, byte-for-byte (copy step is part of the task; CI has
  no access to the private repo, so the copy is pinned and reviewed at update time).
- Test asserts: decode → exact email, exact key bytes, exact fingerprint hex, exact
  created_at, key_type `x25519`; tampered-single-byte variant fails signature verification;
  known-kid/unknown-kid variants drive rule C3-2.
