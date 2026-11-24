# Feature Specification: CKD hosted-directory client support (keys.mdstn.dev)

**Feature Branch**: `007-ckd-hosted-directory`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Support the hosted CKD server (madstone-tech/ckd-server, keys.mdstn.dev): token-authenticated publish/unpublish, rotation contract (fingerprint + proof-of-possession, 409 handling), verify lookup-response signatures, honor key_type, protocol doc updates, and a cross-repo contract fixture test. Target release: v0.4.0."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Publish and unpublish with a directory token (Priority: P1)

A user who verified their email at keys.mdstn.dev receives a one-time directory token. The user
runs the CLI to publish their public encryption key under their email address, so that any other
Cipher sender can encrypt to `user@example.com` without out-of-band key exchange. The user keeps a
copy of the token. Later the user removes the key from the directory with the same token.

**Why this priority**: without authenticated publish, the hosted directory stays empty and the
whole feature delivers nothing. This is the minimum path to value (PRD §9 item 2, the CLI
round-trip).

**Independent Test**: fully testable against a local server stub (or the live endpoint once DNS
is live): publish with token returns success and the published fingerprint; publish without
token fails with an authentication error; unpublish removes the binding.

**Acceptance Scenarios**:

1. **Given** a valid token and a default X25519 key in the local key store, **When** the user
   runs the publish command with an email address, **Then** the key is published over
   authenticated request and the CLI reports success with the key fingerprint.
2. **Given** no token is supplied (no flag, no environment variable), **When** the user runs the
   publish or unpublish command, **Then** the command fails with a clear error naming how to
   supply the token, and no request is sent.
3. **Given** an invalid or expired token, **When** the user runs the publish command, **Then**
   the command relays the server's authentication-failure response as an error (distinct from a
   network failure), and the local key store is unchanged.
4. **Given** a published key, **When** the user runs the unpublish command with the token,
   **Then** the binding is removed and the server reports success (idempotent on repeat).

---

### User Story 2 - Rotate or re-bind through the server's possession rules (Priority: P2)

The user's key changed (or their binding was unpublished and is still inside the tombstone
window). The publish attempt now requires the current binding fingerprint plus a
proof-of-possession artifact. The CLI sends the fingerprint of the key it publishes and, when the
server answers that a current fingerprint is needed, shows the user the required fingerprint so
the rotation can be completed with the right factors.

**Why this priority**: rotation exists from day one for every user whose key changes; without it
users get stuck with an unpublishable stale binding. It builds directly on Story 1's transport.

**Independent Test**: against a server stub that answers with the conflict responses, the CLI
distinguishes the conflict kinds and surfaces the required fingerprint; a request carrying
fingerprint and proof fields passes the stub's validation.

**Acceptance Scenarios**:

1. **Given** a pinned binding with a different current fingerprint, **When** the user publishes
   with token only, **Then** the CLI reports the conflict and displays the server-provided
   current fingerprint with guidance on the factors needed to proceed.
2. **Given** the current fingerprint supplied, **When** the user publishes with token +
   fingerprint + proof-of-possession, **Then** the rotation succeeds and the CLI reports the new
   published state.
3. **Given** a tombstoned email inside the 30-day window, **When** the user publishes with token
   + tombstone fingerprint + proof-of-possession, **Then** the re-bind succeeds as a fresh shape.
4. **Given** a wrong fingerprint or an invalid proof, **When** the user publishes, **Then** the
   CLI relays the server's specific rejection as an error, and does not retry automatically.

---

### User Story 3 - Sender verifies directory responses before trusting them (Priority: P2)

A sender looks a recipient up through the hosted directory. The response carries a service
signature its headers. The CLI/SDK checks the signature against a pinned service public key and
the key id before the key is used or cached; a failed check, or an unrecognized key id, is
surfaced to the user — never silently accepted or silently ignored.

**Why this priority**: this is the anti-poisoning backstop for the global directory (PRD §3
signed responses); it protects every lookup the moment the service is live, ahead of the
transparency log.

**Independent Test**: a fixture response with a valid signature verifies; the same body with one
altered byte fails; a response with an unknown key id is surfaced, not accepted.

**Acceptance Scenarios**:

1. **Given** a well-formed signed response for an email hash, **When** the sender runs a lookup
   that reaches the hosted directory, **Then** the signature verifies against the pinned service
   key and the lookup returns the recipient key.
2. **Given** a response whose signature does not verify, **When** the sender's client processes
   it, **Then** the lookup fails with a signature/integrity error and nothing is cached.
3. **Given** a response signed under an unrecognized service key id, **When** the client
   processes it, **Then** the key-id change is surfaced to the user (TOFU-pin behavior) rather
   than silently accepted.
4. **Given** an unsigned response (headers absent), **When** the client processes it from the
   hosted directory, **Then** the client treats it as a failed integrity check.

---

### User Story 4 - Directory answers carry the key type and clients honor it (Priority: P3)

A response may carry a key-type field. Clients that understand the declared type store and use
the key under that type; clients seeing an unknown type surface it rather than crashing. The
local trust-on-first-use cache distinguishes entries per key type so a future second key type
cannot be confused with an existing pinned one.

**Why this priority**: forward-compatibility wiring; today every published key is one type, so
correct behavior today is trivial, but the cache-schema decision must land now to avoid a
breaking change later.

**Independent Test**: a fixture response with the known type round-trips through lookup and
cache; a response with an unknown type is surfaced and not cached as if it were the known type.

**Acceptance Scenarios**:

1. **Given** a response declaring the known key type, **When** the lookup result is cached,
   **Then** the cache distinguishes it by (recipient, key type) so different types do not
   overwrite each other.
2. **Given** a response declaring an unknown key type, **When** the client processes it, **Then**
   the client surfaces the unknown type as an error or warning and does not silently treat it as
   the known type.
3. **Given** a response with no key-type field (older servers), **When** the client processes it,
   **Then** the client applies the known default type (backward compatible).

---

### User Story 5 - Wire-contract drift is caught by a cross-repo fixture test (Priority: P3)

Maintainers of both repositories need a guarantee the client decoder never drifts from the
server's wire format. A byte-exact fixture (the server's contract fixture) is pinned in this
module's tests; the decoder must round-trip it exactly. Any wire change fails this test in this
repo before it ships.

**Why this priority**: prevention, not user value — but cheap and it enforces PRD §12's no-drift
rule permanently.

**Independent Test**: the pinned fixture test runs alone; any change to the decode shape or
field semantics breaks it.

**Acceptance Scenarios**:

1. **Given** the pinned server fixture (a real success response body), **When** the client
   decodes it, **Then** every field (email, key bytes, fingerprint, creation time, key type)
   matches the fixture exactly.
2. **Given** a change to the wire contract in either repo, **When** CI runs, **Then** the
   fixture test fails and the change is blocked until both repos update the fixture together.

---

### Edge Cases

- What happens when the server returns the fingerprint-required conflict but the CLI's stored
  key does not match the server's current fingerprint at all (someone else holds the binding)?
  The CLI shows the server's guidance and stops; it never retries or overwrites.
- What happens when the token environment variable and the token flag disagree? The flag wins;
  the precedence is documented in the command help.
- What happens when the hosted directory is unreachable but the recipient's own domain serves
  the key? The existing domain-first lookup chain still succeeds; the directory remains a
  fallback and the signature failure of the directory never degrades a domain-authoritative hit.
- What happens when the response signature header is present but the key id header is missing?
  Treated as an integrity failure.
- What happens when the cached entry and a fresh response disagree (key change)? Today a cache
  hit is served without revalidation, so a changed key is noticed only after the cache is
  cleared. Automatic refetch-and-compare surfacing needs a revalidation policy and is out of
  scope for this feature; the per-fetch response signature (US3) is the tamper backstop in v1.
- What happens when unpublish is run for an email the token does not own? The server's
  authentication/authorization failure is relaid; the CLI does not report success.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The publish and unpublish commands MUST accept a directory token via a command
  flag and via an environment variable, and MUST fail with guidance when neither is present.
- **FR-002**: The publish and unpublish commands MUST send the token as a Bearer authorization
  header on every request to the directory's publish endpoints.
- **FR-003**: Commands that talk to the hosted directory MUST default their server URL to the
  hosted directory address, so no explicit server configuration is needed for the normal path.
- **FR-004**: The publish request MUST include the fingerprint of the key being published, plus
  a proof-of-possession artifact, and MUST surface the server's current-fingerprint conflict with
  the returned fingerprint so a correct retry can be built.
- **FR-005**: The client MUST verify the hosted directory's response signature (pinned service
  public key, covered content = recipient hash + response body) before accepting, using, or
  caching a hosted-directory lookup result; a failed check or missing headers MUST fail the
  lookup with an integrity error.
- **FR-006**: The client MUST compare the response key id against the pinned service key id
  using constant-time comparison, and MUST surface a changed key id rather than silently
  accepting it. For v1 the pinned id ships as a build-time constant next to the pinned public
  key; per-profile pin storage joins when the service announces a second key id.
- **FR-007**: Lookup results MUST carry the declared key type; unknown key types MUST be
  surfaced, and the absence of the field MUST default to the existing key type.
- **FR-008**: The local trust-on-first-use cache MUST key entries by (recipient, key type) so
  distinct key types never overwrite one another; existing caches MUST keep working.
- **FR-009**: The client decoder MUST round-trip the pinned byte-exact wire fixture in the test
  suite; the test MUST fail on any shape or field-semantics change.
- **FR-010**: The protocol document MUST describe the signed-response header, its covered
  content, the service key id and public key, and the publish rotation request/response fields —
  as additive wire descriptions (no container-format change; Constitution III untouched).
- **FR-011**: All new error paths MUST keep the established error-class separation
  (authentication vs. conflict vs. integrity vs. network) end to end, up to distinct exit codes
  where the CLI reports them (Constitution V).
- **FR-012**: Every response-verification and token path MUST handle errors explicitly; secret
  comparisons MUST use constant-time comparison; no token, key material, or derived value may
  appear in logs or JSON output (AGENTS.md output rules).

### Key Entities *(include if feature involves data)*

- **Directory token**: a user-held secret that licenses publish/unpublish for one verified
  email. Held by the user, sent as a header, never stored by the client, never logged.
- **Published binding**: email → public key(+fingerprint, key type, timestamps) as held by the
  hosted directory; read by lookup, written by publish/unpublish.
- **Service signing key**: the hosted directory's public signing key and its key id, pinned in
  the client; the id is pinned as a build-time constant and changes are surfaced.
- **Cached discovery entry**: (recipient, key type) → pinned key, fingerprint, first/last seen;
  extended with key type, kept backward compatible.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user who completed email verification can publish their key with exactly one
  CLI command and no configuration beyond the token. (The publish invocation itself completes
  within one minute of manual execution — acceptance item, not a CI assertion.)
- **SC-002**: Two-machine round trip holds: machine A publishes, machine B encrypts to the email
  through the hosted directory, recipient decrypts — the PRD's definition of done (§9 item 2).
- **SC-003**: Every hosted-directory lookup result accepted into the cache passed signature
  verification (100% of accepted responses verified); tampered fixtures are rejected 100%.
- **SC-004**: The pinned wire fixture decodes byte-exactly in the test suite and fails on any
  contract drift (both repos run the same fixture).
- **SC-005**: All existing tests pass with zero warnings (task ci) and the import-boundary gate
  stays green (the feature adds no app-side imports).

## Assumptions

- The hosted directory (keys.mdstn.dev) honors the frozen wire contract documented in
  `docs/ckd-protocol.md`; its extensions (signed responses, publish fields, key_type) are
  additive and optional for clients, per that document's forward-compatibility note.
- The proof-of-possession artifact for v1 is the fingerprint-plus-token second factor
  ("fingerprint_token" kind), because X25519 keys cannot sign rotation challenges.
- The container format (Constitution III) is untouched by this feature: changes are transport-
  and publish-level, not container semantics, so no new version byte and no vector regeneration.
- SDK surface additions for the cache's key-type field ship under the stable-SDK rule with the
  minor bump to v0.4.0 and stated justification.
- The service public key and key id are distributed in the protocol document (public, in this
  repo); key-id rotation is surfaced, not fatal, per the pin-conflict convention.
- Lookup remains free and ungated everywhere; no plan gating enters this feature (Constitution II).
