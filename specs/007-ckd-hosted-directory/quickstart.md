# Quickstart: validate CKD hosted-directory support

End-to-end validation for feature 007. Run from the repo root. Prerequisite: the ckd-server
repo exists locally at `../ckd-server`.

## 0. Build and unit gates

```bash
task build && task test
```

Expected: build succeeds; existing suite green including the new fixture test
(`internal/testdata/ckd/lookup.json` decodes byte-exactly; tamper and key-id tests fail open
closed — negative cases produce errors, positive cases pass).

Full gate when touching shared surfaces:

```bash
task ci && task fork-boundary
```

## 1. Wire contract against the server's local mode

Start the server (its contract is the reference):

```bash
cd ../ckd-server
KD_SIGNING_KEY=$(openssl rand -base64 64) ./dist/bootstrap -local   # :8080
```

From cipher-core, point the CLI at it (override only for the test):

```bash
CIPHER_SERVER_URL=http://localhost:8080 KD_TOKEN=test-local-token \
  ./mdstn-cipher keys publish --email alice@example.com
```

Expected: publish succeeds against the local store; unpublish succeeds on repeat.

## 2. Signed-lookup verification

Serve the pinned success fixture through a stub with a valid signature (the server's local mode
signs responses with the `KD_SIGNING_KEY` you generated — the pinned public key pair in
`docs/ckd-protocol.md` applies to prod, so for the local check, either run the stub from the
contract test, or verify signature logic through the unit path).

Unit-level proof (no server needed):

```bash
go test ./internal/adapters/ckd/ -run 'TestFixture|TestSignature|TestKeyID' -v
```

Expected: fixture round-trips exactly; flipping one body byte fails; unknown key id is
rejected with a pin-conflict error, not silently accepted.

## 3. Conflict matrix (rotation)

```bash
go test ./cmd/ -run 'TestPublishConflict' -v
```

Expected scenarios in the stub: token-only publish against a pinned binding →
`current_fingerprint_required` surfaced with the server's fingerprint; publish with
fingerprint + poc → success with rotation; invalid poc → possession error relayed.

## 4. Cache migration preserves old rows

```bash
go test ./internal/adapters/sqlite/ -run 'TestCKDCache' -v
```

Expected: a pre-migration cache (old schema) opens; rows read back with `key_type=x25519`;
set/get on two key types for one email returns independent entries.

## 5. Live round-trip (once keys.mdstn.dev is live)

1. Verify your email at https://keys.mdstn.dev and copy the one-time token.
2. From machine A: `mdstn-cipher keys publish --email you@example.com --kd-token <token>`.
   Expected: `✓ Published` + fingerprint.
3. From machine B: `mdstn-cipher encrypt report.pdf --for you@example.com`.
   Expected: recipient lookup resolves through the hosted directory; container written.
4. Recipient decrypts as normal. Expected: plaintext matches.
5. Rotate drill: publish again with token only → CLI shows the
   `current_fingerprint_required` conflict and the current fingerprint; re-run with
   fingerprint + poc → success.

## 6. Docs check

```bash
grep -n "X-Mdstn-Kd-Signature" docs/ckd-protocol.md
```

Expected: a section describing signed responses, covered content, service key id + public key.
