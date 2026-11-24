# Security Policy

Supported version: **v0.3.1 and later**. The container format is frozen at `0x03`
(`docs/format-spec.md` §Governance); a format change requires a new version byte and a
new release tag.

## Reporting a vulnerability

**Do not open a GitHub issue for a security problem.** Public issues can expose
exploitable details before a fix lands.

Report by email: **security@madstone.io**

- Write "cipher-core security" in the subject.
- Include: affected version (commit or tag), the command or API path, expected versus
  actual behavior, and a minimal reproduction. Text is fine; a small test file helps.
- Do not send proof-of-concept ciphertext that exploits a real key you hold; use a
  throwaway password or key you generate for the report.

You can encrypt sensitive detail to us (PGP pending — plain email is fine for a first
report). We acknowledge reports within **3 business days** and give a first assessment
within **10 business days**.

## What is in scope

The vulnerabilities we consider reportable:

- **Container format** (`docs/format-spec.md`, version `0x03`): ways for a parser or
  decoder to accept or decrypt data that the spec says must fail — tamper detection,
  header MAC, per-chunk authentication, truncation, reordering, canonical encodings.
- **Crypto primitives and streams**: AES-256-GCM, HKDF, Argon2id, X25519 (key handling,
  low-order point checks, nonce construction), anything that changes the guarantees
  §Security of the format spec makes.
- **Key handling and storage**: SQLite key databases, key exports, the CKD protocol
  (`docs/ckd-protocol.md`), session caches, passphrase checks.
- **Write paths**: output files replacing a file they were not given a path for
  (staged-write guarantees), the header's `original_filename` being treated as a path.
- **The CLI, the SDK surface (`pkg/cipher`, `pkg/cipherports`), and the MCP server**
  (`internal/mcp.Serve`) when a behavior differs from a documented guarantee.

## What is out of scope

These are documented design decisions, not vulnerabilities (`docs/format-spec.md`
§Limitations):

- **Method 3 cannot tell a wrong password from a damaged header** — by design, after the
  header MAC verifies.
- **A damaged recipient block reads as "not a recipient"** — recipient blocks name no
  recipient.
- **No sender authentication** — the format does not prove who made a file. Anyone with a
  recipient's public key can encrypt to them. Sign outside the format if you need it.
- **Method 5 (Shared Key) files are non-recoverable** without the sharing protocol that
  establishes the policy key; it is not derivable from a recovery phrase.
- Denial of service by giving unusually large or malformed input where the code bounds
  the damage (we still want to hear about *missing* bounds).
- Reports about other Madstone products (`ghcr.io/madstone-tech/mdstn-cipher`,
  the hosted application) have their own process.

## Disclosure

We coordinate with the reporter:

1. We confirm, assess severity (CVSS 3.1 as guidance), and agree a fix plan with you.
2. Fix target: within **90 days** of your first report for high and critical, sooner for
   actively exploited issues. If a fix slips, we tell you why and give a new date.
3. On release: a GitHub Security Advisory (GHSA) names you for credit unless you ask to
   stay anonymous, and the `CHANGELOG.md` entry for that version lists the fix. A CVE is
   requested where the issue merits one.
4. We pre-announce to users who run the fixed version before disclosure when timing allows.

## Build and verification for reports

Reports that reference source should name a tag: build `v0.3.1` exactly as released
(`goreleaser`, Go 1.27.1) so we can compare like for like. `go install
github.com/madstone-tech/cipher-core/cmd/mdstn-cipher@vX.Y.Z` is the fastest reproduction
build; the Homebrew cask serves the release binaries.
