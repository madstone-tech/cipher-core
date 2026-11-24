# PRD — keys.mdstn.dev (Cipher Key Directory, hosted)

**Status:** draft for review · **Owner:** Andhi Jeannot · **Target repo:** NEW private repo (org-owned, name TBD) · **Date:** 2026-11-24

Build decision recorded in-session: identity = any verified email · verification = loop-once → API token · overwrite = proof-of-possession · runtime = Go + Postgres in a private repo · token flow = web page · v1 = lookup + publish + verify + CLI Bearer + DNS + `key_type` · abuse set = rate + Turnstile + disposable list + no-enumeration + signed responses · done = live + CLI round-trip + load/security gates · metrics = ops only.

---

## 1. Problem

`mdstn-cipher encrypt --for someone@gmail.com` today fails for everyone except users of a Cipher
instance that serves their domain's `/.well-known` endpoint. The lookup chain in cipher-core is:
local TOFU cache → recipient's domain → Madstone hosted directory (`internal/adapters/ckd/client.go:56-88`)
— and step 3 points at a domain that does not resolve (`keys.mdstn.dev` is NXDOMAIN). Self-hosted
orgs can already serve their own addresses. **Everyone on a personal mailbox cannot discover anyone,
and nobody can discover them.** The protocol for this directory already exists and is normative:
`cipher-core/docs/ckd-protocol.md` ("What CKD is (built today)" + wire format). This PRD covers
standing up the hosted directory as a **standalone service**, per the protocol doc's own extraction
note (§ "the directory can be extracted
into a shared identity-discovery service without a breaking schema change").

Out of scope (later phases, same repo): federation pointer-registry mode, key transparency log.
In scope now: the global full-key directory with verified publishing.

## 2. Users and jobs

| User | Job |
|---|---|
| Individual (gmail-style mailbox) | Publish their public key so `--for me@gmail.com` works; rotate if their key changes |
| CLI/SDK sender | Look up a recipient by email and encrypt without out-of-band key exchange |
| Cipher (closed app) operator | Not affected — its instance keeps serving `@<its-domain>` authoritatively; the directory is only a fallback for domains with no Cipher |
| Madstone ops | Run a public endpoint that cannot be used to enumerate emails or poison bindings |

## 3. Wire contract (frozen by clients — do not change)

All of this is already implemented in cipher-core's client and normative in the protocol doc. The
service must honor it byte-for-byte.

- Key identity: `email_hash = hex(sha256(lowercase(trim(email))))`.
- Key fingerprint: `hex(sha256(public_key_der_or_raw))` (spec) — returned as `fingerprint`.
- Lookup: `GET /.well-known/mdstn-cipher/{email_hash}` → `200 {"email","public_key","fingerprint","created_at"}` (JSON, same shape as cipher-core client decode `internal/adapters/ckd/client.go:130`) plus a **new optional `key_type`** field (`"x25519"`; clients honor it forward-compatibly — protocol doc §Forward-compatibility).
- Not found: HTTP 404, non-descript body (no oracle distinctions beyond 200/404/429/5xx).
- Publish: `POST /api/v1/ckd/publish` `{"email","public_key"}` (base64 key) → `{"status":"published","email","email_hash"}`; authenticated via `Authorization: Bearer <token>`.
- Unpublish: `DELETE /api/v1/ckd/unpublish` `{"email"}` → `{"status":"unpublished"}`.
- Status: `GET /api/v1/ckd/status?fingerprint=…` → `{"published":bool,"fingerprint"}`.
- **Signed responses (v1):** lookup responses carry a `X-Mdstn-Kd-Signature` header (ed25519 service key, key id in `X-Mdstn-Kd-Keyid`), signature over `hash + "\\n" + body`. Pairs with TOFU and is the precursor to the Phase-3 transparency log. Key published in the repo and in `docs/ckd-protocol.md`.

## 4. Identity, verification, tokens

1. **Page** (`https://keys.mdstn.dev` — minimal static-featherweight page, no accounts): user enters
   an email → POST `/verify/start {email}` → rate-limited, Cloudflare Turnstile-gated.
2. Server emails a single-use link (10-minute TTL, token) → `GET /verify/confirm?code=…`.
3. On confirm: record `(email → verified_at)`, generate `kd_token` (random 32 bytes, shown once,
   stored hashed), display it. This token is **the license to publish for that email**.
4. CLI/SDK: `mdstn-cipher keys publish` reads `KD_TOKEN` env or `--kd-token` (cipher-core PR —
   `cmd/keys.go:428` currently supports only `CIPHER_SERVER_URL` + no auth header; add token +
   `Authorization` header; no code change server-side beyond accepting the header).
5. Re-verification is only needed to re-bind after a proof-of-possession rotation was authorized
   via an old fingerprint that no longer exists (see §5) — i.e. effectively never in the happy path.

Email storage: stored plaintext (needed to send mail, resolve support, show sender "this is
alice@…"). Acceptable because emails were user-supplied, not harvested. Hash is the lookup key;
email is never returned through the public endpoint except in the JSON `email` field (which the
wire contract mandates).

## 5. Anti-squat: binding lifecycle (the hard rule)

State machine per `email_hash`:

| State | Transition | Rule |
|---|---|---|
| empty | publish (token) | allowed — becomes **pinned** |
| pinned | publish (token + current fingerprint) | **rotation**: allowed if request includes `fingerprint` matching the stored one AND a proof-of-possession artifact: the signed challenge `/mdstn-kd/rotate-v1/{email_hash}/{new_fingerprint}` signed by the *private key of the currently published public key* (X25519 key → use the `mdstn-cipher` signing convention; if the key pair can't sign, accept `fingerprint + current kd_token` as second factor) |
| pinned | publish (token only) | **rejected** with `409 current_fingerprint_required` (returns the current fingerprint so the user can build the proof) |
| pinned | unpublish (token) | allowed → state becomes **tombstone**, tombstone stores the last fingerprint for the rotation-proof above; tombstoned email re-publishes with token + that fingerprint (proves you were the last owner) |
| tombstone (30 days elapsed) | publish (token) | fresh binding allowed (grace expiry) |

Rationale: possession-based rotation blocks the "register before the real user" attack and the
"stolen token re-binds" attack (a stolen token alone cannot rotate); tombstones stop the
"release-then-squat" abuse of the 30-day window by pre-publishing users.

## 6. Abuse controls (v1, all four chosen + signing)

- Public lookup: per-IP rate limit 30/min burst 10 (tunable via env), uniform timing between hit
  and miss (constant-time DB fetch path), **no email enumeration**: hash-only input.
- Verification start: Turnstile + per-IP 5/hour + disposable-domain blocklist (`mailinator`,
  `tempmail`, et al. — static list in repo).
- Publish/status/unpublish: authenticated (token) + per-token rate limit 60/min.
- Storage: never respond differently for "hash exists, email differs" (hash is the unique key).
- No bulk export endpoint; the pgx table is the only copy.

## 7. Architecture

Single small Go service, one Postgres.

```
Caddy (TLS, ACME) ──> ckd-server (Go stdlib http, no framework needed at this size)
                        ├── GET /.well-known/mdstn-cipher/{hash}   (public, rate-limited)
                        ├── GET/POST/DELETE /api/v1/ckd/*          (Bearer, rate-limited)
                        ├── GET/POST /verify/*                     (Turnstile, email loop)
                        └── Postgres: published_keys(
                              email_hash PK, email, public_key BYTEA, fingerprint,
                              key_type TEXT DEFAULT 'x25519',
                              created_at, verified_at, last_rotation_at,
                              tombstone_fingerprint, tombstone_until)
                        Mail: transactional send (Postmark/SendGrid free tier) via env-provided key
```

Lift from cipher-core (protocol source of truth): `hashEmail` semantics, TOFU cache expectations,
wire JSON, `docs/ckd-protocol.md`. Lift shapes from the existing internal server implementation
(private reference, not importable): the well-known/publish handlers, the pgx directory query set,
TLS termination via Caddy, and the compose/ACME deploy pattern. New in this repo: token issuance,
the rotation proof, signing, Turnstile, disposable list,
load hardening.

## 8. Infra & DNS

- `keys.mdstn.dev` A/AAAA → the box (Cloudflare or the existing VPS provider);
  Caddy auto-ACME with Let's Encrypt (per the existing Caddyfile swap path).
- Deploy: `compose.yml` (app + caddy + postgres) + GitHub Actions CI (build, test, `goreleaser`
  artifact, deploy on main tag — pattern copy from cipher-core's release.yml, minus casks/Docker
  signing unless wanted).
- Secrets in 1Password or an `.env` file: `KD_SIGNING_KEY`, SMTP key, Turnstile secret,
  `DATABASE_URL`.

## 9. Definition of done (the line chosen)

1. Live at `https://keys.mdstn.dev` with a valid cert; `curl` round-trip works.
2. **CLI round-trip, two machines:** machine A publishes (token from the web flow); machine B
   `encrypt --for <email> --kd <…>` resolves and encrypts; recipient decrypts.
3. Load: lookup path ≥200 rps sustained on the target host, p99 < 50 ms, no errors in 5-min soak.
4. Security pass: token page reviewed (no open redirect, CSRF on verify POST, Turnstile enforced),
   no hash/email in logs or metrics, signing verifies with the published public key, negative tests
   for the rotation matrix (§5 all rows).
5. Repo hygiene: README, CHANGELOG, CI green, tests for every handler and rotation rule,
   `goreleaser` snapshot artifact, private repo for v1 (public later if wished).

## 10. Metrics (ops only)

Uptime, lookups/s, p50/p99 latency, publish success rate, verification completion rate (counts
only — no funnels), abuse rejections (429s, Turnstile failures). No email analytics beyond
counts. Alert if: 5xx rate > 0.5%/5 min, p99 > 200 ms, Postgres disk, cert expiry, mail bounce
rate > 5%.

## 11. Explicit non-goals for v1

Federation / pointer-registry mode (Phase 2); transparency log (Phase 3); web encryption UI
(stays in the hosted app); passkey/account model (same); migration of the hosted app's existing
`published_keys` table (separate data plane); self-hosted directory federation handshake.

## 12. Risks

| Risk | Mitigation |
|---|---|
| Email verification abused → spam bindings | Turnstile + rate + disposable list + token only after click-through |
| Stolen API token re-binds someone | §5 possession rule — stolen token alone yields 409, not a takeover |
| Host loses DNS → silent lookup failure for everyone | Cipher-core cache keeps TOFU pins offline (already built); publish a status page |
| Private key of dir signing key leaks | Key id in header allows rotation; sign key never in image (env) |
| Spam through verification mail | Rate + Turnstile at start, not on send — plus per-email resend limit 1/hour |
| cipher-core CLI drift from wire contract | Contract test in both repos (fixture JSON), never re-parse differently |
