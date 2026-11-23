# Contract: Container version `0x03` (format v2)

> **Superseded in part by `specs/002-qa-remediation/`** (2026-11-05). The app was not released, so
> feature 002 removed the `0x01` format (no v1 read path, no v1 vectors) and changed `0x03`
> before its first tag: header MAC, canonical keys, strict base64, canonical final frame. Read
> the v1 and format-v2 statements below as history.

This contract is the source for the new section in `docs/format-spec.md`. Implementation details
(R3 in `research.md`) MUST match it byte for byte.

## Header

```
Magic "MDST"(4) | Version 0x03(1) | Method(1) | HeaderLen u16be(2) | HeaderJSON(HeaderLen)
headerAAD = bytes[0 : 8+HeaderLen]
```

Common JSON fields: `chunked` (bool, required), `original_filename`, `encrypted_at`.

| Method | Required JSON fields | Forbidden JSON fields |
|---|---|---|
| `0x02` X25519 | `recipients`: 1-16 × `{ephemeral_pub_key, nonce, wrapped_cek}` | `key_id`, `recipient_key_id`, `ephemeral_pub_key` (top level), `nonce` (top level), `encrypted_data`, `fingerprint_hint` |
| `0x03` password | `kdf:"argon2id"`, `salt` (16 B), `m:65536`, `t:3`, `p:4` | any other KDF or parameters |
| `0x05` shared key | `policy_id` | — |

## Key derivation

```
# Method 2, per recipient block
shared = X25519(eph_priv, R_pub); reject if all zero
kek    = HKDF-SHA256(ikm=shared, salt=eph_pub || R_pub, info="mdstn-cipher/v2/wrap", L=32)
wrapped_cek = AES-256-GCM(kek, nonce, cek, aad="mdstn-cipher/v2/wrap-cek")   # 48 bytes

# Method 3
key = Argon2id(password, salt, m=65536 KiB, t=3, p=4, L=32)
```

The decryptor derives `R_pub` from its private key. It tries each block with each usable key.

## Body

```
chunked=false:  nonce(12) || AES-256-GCM(key, nonce, plaintext, aad=headerAAD)

chunked=true:   base(12) || frame_0 .. frame_n || u32be(0) || EOF
  frame_i = u32be(len_i) || ct_i
  nonce_i = base XOR (0^4 || u64be(i))
  ct_i    = AES-256-GCM(key, nonce_i, pt_i, aad=headerAAD || u64be(i) || u8(i == n))
  |pt_i| = 65536 for i < n;  0 ≤ |pt_n| ≤ 65536;  n ≥ 0 (an empty input is one final frame)
```

## Tamper contract (v1 and v2)

Exit codes: 1 parse error, 2 `ErrHeaderAuthFailed`, 3 `ErrNotARecipient`, 4 `ErrWrongPassword`.
"Key class" is a GCM failure of the single frame or of chunk 0 in its own place. It gives exit 2,
or exit 4 for method 3. `TestAADTamperMatrix` (internal/adapters/crypto/aad_tamper_test.go) runs
every row on the committed fixtures.

| Mutation | v1 result | v2 result |
|---|---|---|
| Any header byte, header still parses | key class: exit 2 (method 3: exit 4) | same |
| Any header byte, header does not parse | exit 1 | exit 1 |
| A byte of every `wrapped_cek` (method 2) | exit 2 (the hint names the block) | **exit 3** (see note 1) |
| Body bit flip, chunk 0 | key class: exit 2 (method 3: exit 4) | same |
| Base nonce bit flip | exit 2 (derived-nonce check) | key class: exit 2 (method 3: exit 4) |
| Body bit flip, chunk k > 0 | exit 2 | exit 2 |
| Swap two frames (incl. frame 0) | exit 2 | exit 2 (see note 2) |
| Repeat a frame | exit 2 | exit 2 |
| Remove a frame (incl. frame 0) | exit 2 | exit 2 |
| Forged length < 16 or > 65552 | exit 2, no large allocation | same |
| Truncate at a boundary + terminator | **succeeds (v1 limitation)** | exit 2 |
| Truncate without terminator, or inside a frame | exit 2 | exit 2 |
| Bytes after the terminator | exit 2 | exit 2 |
| Version byte `0x01 → 0x03` | exit 1 (v1 headers carry v1-only members) | — |
| Version byte `0x03 → 0x01` | — | method 2: exit 3; stream: exit 2; single frame: key class |

Notes (changes from the first draft of this table, which said exit 2 for every header row):

1. A v2 recipient block names no recipient. A damaged block cannot be told apart from a block for
   another key, so the decryptor reports `ErrNotARecipient`. v1 reports exit 2, because the
   `fingerprint_hint` names the block that fails.
2. A swap that moves another frame to position 0 is exit 2 also for method 3. The v2 decoder
   proves the tamper: frame 0 opens as chunk j for some 1 ≤ j ≤ 16. Beyond 16 frames it reports
   the key class.
3. A v2 header read with v1 rules parses. Its blocks have no `fingerprint_hint`, so method 2
   finds no block (exit 3). A v2 stream body fails the v1 derived-nonce check of chunk 0 (exit 2).
4. Method 5 has the same classes. The CLI does not decrypt method 5 (exit 1).

In every failure row, the output path has no file.
