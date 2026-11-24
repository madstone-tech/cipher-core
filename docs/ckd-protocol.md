# Madstone Cipher — CKD Protocol

**CKD (Cipher Key Directory)** is Cipher's email-based public-key discovery mechanism: given an
email address, find the recipient's public key so you can encrypt to them without exchanging keys
out of band. This document describes the protocol **as built today**, and then — clearly
separated — the **future federation** model that is designed but **not yet implemented**.

The directory binds `email → public key`. Because that binding is the entire value of CKD, the
security model (now and in the future) is centered on preventing **key poisoning**.

---

## What CKD is (built today)

CKD is a per-instance directory service. The server side (not part of this module) backs it with
a `published_keys` table holding `(email_hash, email, public_key, fingerprint, created_at)`,
keyed by `email_hash`. This module ships the CKD discovery **client**
(`internal/adapters/ckd`) and the cache/policy repositories.

- **`email_hash = sha256(lowercased, trimmed email)`** (hex). Emails are hashed so the directory
  never exposes addresses in its lookup key.
- **`fingerprint = sha256(public key)`** — used to identify a key (e.g. publish-status checks).
- **TOFU (trust-on-first-use).** The first key seen for a contact is pinned; later changes are
  surfaced to the user rather than silently accepted.

### Deployment scope

The same protocol has two very different scopes depending on auth mode:

| Mode | CKD scope | Who's in it |
|------|-----------|-------------|
| **Self-hosted** (local auth) | Local to the deployment | The org/individual running that instance |
| **Hosted** (Madstone-run) | Global | All hosted users |

A self-hosted user cannot currently look up a hosted-user's key (or another org's key) without a
federation mechanism — that gap is what the future work below addresses.

### Operations

CKD is exercised through these endpoints:

| Operation | Endpoint | Auth | Notes |
|-----------|----------|------|-------|
| Publish | `POST /api/v1/ckd/publish` | session | Publishes the caller's key under their account email |
| Unpublish | `DELETE /api/v1/ckd/unpublish` | session | Removes the caller's directory entry |
| Status | `GET /api/v1/ckd/status?fingerprint=…` | session / API key | Is this key published? |
| Lookup (authenticated) | `GET /api/v1/ckd/lookup/{email}` | session / API key | Audit-logged; **free, never gated** |
| Public discovery | `GET /.well-known/mdstn-cipher/{hash}` | **public** | Unauthenticated discovery by `email_hash` |

**Lookup is always free** on every surface (CLI `lookup`, MCP `lookup_key`, API, and web) and is
never subject to plan gating.

### Wire format (JSON)

The public discovery endpoint `GET /.well-known/mdstn-cipher/{hash}` and the authenticated
lookup both return:

```json
{
  "email": "alice@example.com",
  "public_key": "<base64-encoded public key>",
  "fingerprint": "<sha256 hex of the public key>",
  "created_at": "2026-06-11T12:00:00Z"
}
```

Publish returns `{"status":"published","email":"…","email_hash":"…"}`; unpublish returns
`{"status":"unpublished"}`; status returns `{"published":<bool>,"fingerprint":"…"}`.

> **Forward-compatibility note.** The response format is designed to carry a `key_type` field
> and the TOFU cache keys on `(email_hash, key_type)`, so the directory can be extracted into a
> shared identity-discovery service without a breaking schema change. Honor `key_type` in any
> client that consumes these responses.

### DNS / self-hosting setup for the `.well-known` endpoint

The discovery endpoint is public and unauthenticated. To make your instance discoverable:

1. **DNS:** point your Cipher hostname (e.g. `cipher.example.com`) at the host running your
   reverse proxy, with valid TLS.
2. **Proxy:** do not block `/.well-known/` — the server serves the directory response there. Front
   the binary with Caddy/nginx.
3. **Rate limit:** keep `RATE_LIMIT_PER_MINUTE` set; never expose bulk enumeration of the
   directory.

Verify a published key resolves:

```bash
HASH=$(printf 'alice@example.com' | shasum -a 256 | cut -d' ' -f1)
curl -s "https://cipher.example.com/.well-known/mdstn-cipher/$HASH"
```

---

## Signed responses (hosted directory, additive)

Lookup responses from the hosted directory (`keys.mdstn.dev`) carry an
ed25519 service signature. The self-hosted `.well-known` endpoint stays
unsigned — clients verify signatures only on hosted-directory results.

| Header | Content |
|---|---|
| `X-Mdstn-Kd-Signature` | base64-std ed25519 signature |
| `X-Mdstn-Kd-Keyid` | service key id, currently `kd-2026-11` |

- **Covered content**: `email_hash + "\n" + raw_response_body` (the exact
  bytes the server sent — the signature is over the body, not the decoded
  fields).
- **Pinned service public key** (base64-std, 32 bytes):

  ```
  gqd2RnaBd5ZShK1AIVk5KGMzIemiQ+K2OPF3CLIASh8=
  ```

- **Client rules** (implemented in `internal/adapters/ckd/service_key.go`):
  verify the signature before using or caching a hosted-directory lookup
  result; compare the key id with a constant-time comparison; a missing
  header, a failed verification, or an unrecognized key id is surfaced as an
  integrity failure — never silently accepted and never cached. A changed key
  id is surfaced to the user (key-rotation signal).
- **Key rotation** (server side): publish the new public half and key id in
  this document, then bump the id; clients surface the id change rather than
  auto-trusting it.
- **Forward-compatibility**: the response body may carry a `key_type` field
  (`"x25519"` today). Clients absent-field default to `x25519`, honor a known
  declared type, and surface an unknown type as an integrity failure (nothing
  cached). The TOFU cache keys entries on `(email, key_type)`.
- **Publish rotation (hosted directory)**: `POST /api/v1/ckd/publish`
  accepts two additive fields beyond the frozen base shape — `fingerprint`
  (hex of the key being published) and `poc` (`{"type":"fingerprint_token"}`:
  fingerprint + current kd_token as the proof-of-possession factor). A
  pinned binding with token-only publish answers
  `409 {"error":"current_fingerprint_required","current_fingerprint":"…"}` —
  the CLI surfaces the returned fingerprint so the rotation can be rebuilt;
  it never retries automatically.

---

## Future: federation (design, not yet built)

> **Status:** the following is a **design**, not shipped behavior. None of the resolution
> chain, global registry, or transparency-log mechanics below exist in the current binary.

The goal is to let a self-hosted user look up a hosted-user's key (and vice-versa, and across
orgs) **without** turning the global directory into a single point of failure or a trust
bottleneck. The model combines **domain-authoritative discovery (WKD-style)**, a **global
registry fallback**, and **trust-on-first-use**.

### Lookup resolution order (for `alice@acme.com`)

1. **Local TOFU cache** — fast, offline, pinned. If present and fresh, use it (flag on change).
   This is what makes encryption to known contacts survive any directory outage.
2. **Domain-authoritative** — resolve `acme.com` → fetch its
   `/.well-known/mdstn-cipher/{hash}`. Acme's own self-hosted Cipher is authoritative for
   `@acme.com` addresses.
3. **Global CKD fallback (Madstone-run directory)** — only if the domain runs no Cipher / has no WKD record
   (individuals on the hosted service, or domains that opted into the global registry).
4. **Pin** the result via TOFU; **surface conflicts** between sources rather than silently
   choosing.

### Publish model

- A domain's own instance is authoritative for its addresses (publish locally → served from that
  domain's `.well-known`).
- For the **global** registry, **verified email ownership** (proof-of-control) gates publishing
  so the global index can't be spammed with fake bindings. The recommendation leans toward the
  global registry storing **pointers** (domain stays authoritative) rather than caching full
  keys.

### Security model (the threat is poisoning)

Defenses, strongest-first:

- **Domain-authoritative (WKD):** only `acme.com` can publish `@acme.com` keys — eliminates
  cross-domain impersonation by construction.
- **TOFU + pinning:** first lookup pins; later changes are flagged — detects post-hoc poisoning
  even within a domain.
- **Verified email ownership before global publish:** proof-of-control gate.
- **Key transparency log (advanced):** an append-only, verifiable log of bindings so clients can
  detect a directory serving different keys to different people (equivocation) — CT-log /
  Keybase-sigchain / Google Key Transparency style.

Privacy / abuse: keep emails hashed; never expose bulk enumeration; rate-limit lookups; use short
TTLs on directory responses plus a revocation signal that propagates (publish/unpublish
invalidates, TOFU periodically re-validates). **Conflict resolution:** domain-authoritative wins;
the global CKD defers to a domain that serves its own WKD; surface conflicts to the user rather
than auto-picking.

### Suggested phasing

1. **Phase 1 — Domain-authoritative resolution + TOFU (open, in the binary).** Add email-domain →
   endpoint resolution and the local→domain→(none) fallback chain on top of the existing
   `.well-known` endpoint and TOFU cache. Self-hosted ↔ self-hosted federation works with zero
   central dependency. The one concrete code gap is **email-domain → endpoint resolution + the
   fallback chain** on the lookup side; no schema change beyond honoring `key_type`.
2. **Phase 2 — Global CKD as registry + fallback (Madstone-run).** Verified-ownership publishing;
   index/pointer records; opt-in push from edges; fallback resolution for non-WKD domains.
3. **Phase 3 — Key transparency log (Madstone-run).** A verifiable directory; the high-assurance
   enterprise differentiator.

### Relationship to entitlement

Federation reinforces the "open edge, hosted control plane" split: nothing in the open
binary is gated, and **CKD lookup stays free everywhere**. The global directory and
transparency log are hosted-service capabilities; entitlement flows through the hosted
service, not an offline token, and federation does not reintroduce one.
