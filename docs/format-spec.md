# Madstone Cipher — `.mdstn` File Format Specification

**Container version**: `0x03` | **Date**: 2026-11-04 | **Normative**: this document, plus `internal/testdata/vectors.json`

## Module Layout

The format-carrying Go core lives in this module (`github.com/madstone-tech/cipher-core`).
This specification and the canonical test vectors (`internal/testdata/`) live here.

## Purpose

This document specifies the `.mdstn` encrypted file format produced by Madstone Cipher (`mdstn-cipher`). It is written to be reimplementation-grade: a developer with no access to Cipher source code can read this document, implement the described algorithms, decrypt every committed vector in `internal/testdata/vectors.json`, and refuse every negative fixture with its error class.

## Container Version

There is ONE container format. Its version byte is `0x03`.

| Version byte | Status | Decoder result |
|---|---|---|
| `0x01` | RETIRED (pre-release format of `v0.2.x` modules) | parse error "unsupported version" |
| `0x02` | RETIRED (never released) | parse error "unsupported version" |
| `0x03` | THE format. Frozen since `v0.3.0` (2026-11-08), its first release tag (§Governance). | decoded by this specification |
| other | unassigned | parse error "unsupported version" |

A decoder checks the version byte before it reads the header JSON. Retired bytes MUST NOT get a new meaning, so that an old file never parses under new rules.

**Pre-release `0x03` files.** Development builds `0eb41b9` to `e834a9b` (never tagged) wrote `0x03` without a header MAC. This specification reads the first 32 body bytes of such a file as the header MAC, so the file fails as a wrong password (method 3) or as tamper (method 2). Decrypt such a file with the build that wrote it, then encrypt it again. `0x01` files (`v0.2.x` module tags) cannot be read: there is no v1 reader.

## Byte Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Header (headerAAD): Magic(4) │ Version(1) │ Method(1) │ HeaderLen(2)      │
│                     │ HeaderJSON(HeaderLen)                              │
├──────────────────────────────────────────────────────────────────────────┤
│ Body: HeaderMAC(32) │ chunked=false: Nonce(12) │ CT+Tag                   │
│                     │ chunked=true : BaseNonce(12) │ [Len u32be │ CT+Tag]+ │
│                     │                │ Terminator u32be(0) │ EOF          │
└──────────────────────────────────────────────────────────────────────────┘
```

| Field | Offset | Length | Type | Description |
|-------|--------|--------|------|-------------|
| Magic | 0 | 4 | ASCII | Always `"MDST"` (0x4D 0x44 0x53 0x54). Wrong magic is a parse error. |
| Version | 4 | 1 | uint8 | Always `0x03` |
| Method | 5 | 1 | uint8 | Method byte (below) |
| HeaderLen | 6 | 2 | uint16 BE | Length of the header JSON in bytes |
| HeaderJSON | 8 | HeaderLen | UTF-8 JSON | Header members (§Header JSON) |
| HeaderMAC | 8+HeaderLen | 32 | bytes | `HMAC-SHA256(mac_key, headerAAD)` (§Key schedule) |
| Frames | 8+HeaderLen+32 | variable | bytes | Single frame or stream (§Body) |

```
headerAAD = received_bytes[0 : 8 + HeaderLen]
```

`headerAAD` is the exact received bytes, not a re-serialization. It is the MAC input and the AEAD additional data of every body frame. A changed header byte (the version and method bytes included) fails the header MAC.

### Method Bytes

| Byte | Method | File key |
|------|--------|----------|
| `0x02` | X25519, 1 to 16 recipient blocks | random 32-byte CEK, wrapped once per recipient |
| `0x03` | File password | Argon2id(password, salt, m=65536 KiB, t=3, p=4), 32 bytes |
| `0x05` | Shared key | the 32-byte policy key (§Limitations) |

Any other method byte is a parse error "unsupported method". A decoder MUST NOT interpret the rest of the file.

## Header JSON

HeaderJSON is one JSON object. The Cipher encoder writes it with sorted member names and no spaces. A decoder reads the received bytes and does not serialize them again.

**Common members (all methods)**:

| Member | Type | Rule |
|---|---|---|
| `chunked` | boolean | REQUIRED. `false`: single frame. `true`: stream. |
| `original_filename` | string | Optional and informational. `""` means no name. Otherwise it MUST be a **safe base name**: 1 to 255 bytes of UTF-8, not exactly `.` or `..`, and no `/`, `\`, `:`, C0 or C1 control character (U+0000–U+001F, U+007F–U+009F), or **invisible character**. The invisible characters are this frozen list (Unicode 17 categories Cf, Zl, and Zp: format characters such as zero-width spaces and joiners, bidi controls, the BOM, the soft hyphen, tag characters, and the line and paragraph separators): U+00AD, U+0600–U+0605, U+061C, U+06DD, U+070F, U+0890–U+0891, U+08E2, U+180E, U+200B–U+200F, U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF, U+FFF9–U+FFFB, U+110BD, U+110CD, U+13430–U+1343F, U+1BCA0–U+1BCA3, U+1D173–U+1D17A, U+E0001, U+E0020–U+E007F. Any other value is a parse error. The sender chooses this value: a decryptor MUST NOT use it as a path (§Output path). |
| `encrypted_at` | integer | Optional. Unix seconds. A non-integer value is a parse error. |

**Members per method**:

| Method | Required members |
|---|---|
| `0x02` X25519 | `recipients`: array of 1 to 16 objects `{ephemeral_pub_key, nonce, wrapped_cek}` (base64 of 32, 12, and 48 bytes) |
| `0x03` file password | `kdf: "argon2id"`, `salt` (base64 of 16 bytes), `m: 65536`, `t: 3`, `p: 4`. Any other KDF name or parameter value is a parse error. |
| `0x05` shared key | `policy_id` (non-empty string) |

**Forbidden members (all methods)**: `key_id`, `recipient_key_id`, `ephemeral_pub_key`, `nonce`, and `encrypted_data` at the top level, and `fingerprint_hint` at the top level or in a recipient block. These are the members of the retired `0x01` header. They are forbidden for every method, even with an empty value. Members of another method (for example `salt` in a method-2 header) are unknown members. Other unknown members are permitted (forward compatibility); the header MAC covers them.

### Strict base64

Every base64 header value is RFC 4648 §4 (standard alphabet `A–Z a–z 0–9 + /`) with `=` padding to a multiple of 4 characters. A decoder MUST reject:

- any character outside the alphabet and the final padding, `\r` and `\n` included (some decoders skip CR and LF silently);
- missing or extra padding;
- non-zero padding bits (the unused low bits of the last data character).

Thus each byte string has exactly one encoding. In Go: reject `\r`/`\n`, then `base64.StdEncoding.Strict()`.

### JSON rules

The header JSON MUST also meet these rules, so that two conforming decoders accept the same headers:

- every number is a non-negative integer, written without sign, fraction, or exponent (`1.0` and `1e3` are invalid), and at most 2^53 − 1;
- `NaN`, `Infinity`, and `-Infinity` are invalid (they are not JSON);
- every string is a sequence of Unicode scalar values (a lone UTF-16 surrogate escape such as `"\ud800"` is invalid);
- objects and arrays nest at most 8 levels (the defined members use 3).

These rules apply to unknown members too.

### Header rules

A decoder MUST apply these rules before it runs any KDF or opens any frame. A violation is a parse error (exit 1):

- the version byte is not `0x03`, or the method byte is not 2, 3, or 5;
- the file ends inside the header or inside the header MAC;
- the JSON is invalid, has a duplicate member name or invalid UTF-8, breaks §JSON rules, or is not an object;
- `original_filename` is not empty and not a safe base name;
- a required member is missing, or a member has the wrong type;
- a forbidden member is present;
- a base64 value is not strict, or decodes to the wrong length;
- a method-2 header has 0 or more than 16 blocks;
- a method-3 header has other KDF parameters. Thus a hostile file cannot choose the KDF cost.

Example headers (base64 values shortened):

```json
{"chunked":true,"encrypted_at":1793750400,"original_filename":"test.txt","recipients":[{"ephemeral_pub_key":"…","nonce":"…","wrapped_cek":"…"}]}
{"chunked":false,"encrypted_at":1793750400,"kdf":"argon2id","m":65536,"original_filename":"test.txt","p":4,"salt":"…","t":3}
{"chunked":false,"encrypted_at":1793750400,"original_filename":"test.txt","policy_id":"00000000-0000-4000-8000-000000000005"}
```

## Key Schedule

Each method gives a 32-byte **file key**. Two keys are derived from it:

```
mac_key     = HKDF-SHA256(ikm=file_key, salt=none, info="mdstn-cipher/v2/header-mac", L=32)
payload_key = HKDF-SHA256(ikm=file_key, salt=none, info="mdstn-cipher/v2/payload",    L=32)
header_mac  = HMAC-SHA256(mac_key, headerAAD)
```

(`salt=none` is the RFC 5869 default: 32 zero bytes. The "v2" in the labels names the format generation; the version byte is `0x03`.)

The header MAC commits the header to one file key: HMAC-SHA256 is collision resistant as a function of its key, so a header verifies under at most one file key that anyone can find. AES-GCM alone is not key committing; without the MAC, a method-2 file could carry blocks that wrap different CEKs and a body that opens under each of them, so that two recipients read two different plaintexts. The MAC is also the key check of method 3: a wrong password fails the MAC before any body byte is read.

A decoder MUST verify `header_mac` with a constant-time comparison (for example `hmac.Equal`) before it decrypts any body byte.

### Method 2 (X25519)

The encryptor makes one random 32-byte CEK (the file key). For each recipient public key `R_pub` it makes one block:

```
eph_priv    = random(32);  eph_pub = X25519(eph_priv, 9)
shared      = X25519(eph_priv, R_pub)          # reject an all-zero result
kek         = HKDF-SHA256(ikm=shared, salt=eph_pub || R_pub, info="mdstn-cipher/v2/wrap", L=32)
nonce       = random(12)
wrapped_cek = AES-256-GCM(kek, nonce, cek, aad="mdstn-cipher/v2/wrap-cek")   # 48 bytes
block       = {"ephemeral_pub_key": b64(eph_pub), "nonce": b64(nonce), "wrapped_cek": b64(wrapped_cek)}
```

"Encrypt for yourself" is one block for the default key. Blocks name no recipient: a decryptor finds its block by trial decryption (§Recipient trial).

### Canonical public keys

An encryptor MUST check every recipient public key before it writes a block, and MUST refuse a key that is not canonical (Cipher: `ErrInvalidRecipientKey`, before any output):

1. exactly 32 bytes;
2. bit 255 clear: `R_pub[31] & 0x80 == 0`;
3. the little-endian integer `u < p = 2^255 − 19`;
4. not a low-order point: `X25519(s, R_pub)` is not all-zero for a random scalar `s`.

A non-canonical encoding names the same point as a canonical one, so the ECDH works, but `R_pub` is in the HKDF salt. The owner derives the salt from the canonical encoding of the key, so the owner could not decrypt the file. Rule 4 rejects keys that give no shared secret.

### Method 3 (file password)

```
salt     = random(16)
file_key = Argon2id(password, salt, m=65536 KiB, t=3, p=4, L=32)    # RFC 9106, version 0x13
```

### Method 5 (shared key)

The file key is the 32-byte policy key that `policy_id` names. The sharing protocol makes this key; it is out of scope for the container format (§Limitations).

## Body

The body follows the header MAC. Both framings seal with `payload_key`.

```
chunked=false:  nonce(12) || AES-256-GCM(payload_key, nonce, plaintext, aad=headerAAD)

chunked=true:   base_nonce(12) || frame_0 .. frame_n || u32be(0) || EOF
  frame_i = u32be(len_i) || ct_i                    # no on-wire chunk nonce
  nonce_i = base_nonce XOR (0^4 || u64be(i))
  ct_i    = AES-256-GCM(payload_key, nonce_i, pt_i, aad=headerAAD || u64be(i) || u8(i == n))
  |pt_i| = 65536 for i < n
  |pt_n| = 0 when n = 0 (empty plaintext);  1 ≤ |pt_n| ≤ 65536 when n ≥ 1
```

- `nonce` and `base_nonce` are random for each file. Method 5 uses one policy key for many files, so the nonce MUST NOT be derived from the key.
- `len_i = |pt_i| + 16`. Thus `16 ≤ len_i ≤ 65552`, and `len_i` is never 0. A non-final frame has `len_i = 65552`.
- **Canonical final frame.** An empty plaintext is one final frame of 0 plaintext bytes (`len_0 = 16`). When a stream has more than one frame, the final frame holds at least 1 plaintext byte (`len_n ≥ 17`). The encoder reads one chunk ahead to know which chunk is final, so a plaintext of `k × 65536` bytes (k ≥ 1) ends with a full final frame. Each plaintext has exactly one stream encoding; a decoder MUST reject an empty final frame after a full frame (tamper).
- **Single-frame limit.** Cipher encrypts files of 1 MiB (2^20 bytes) or more with `chunked=true`, and smaller files with `chunked=false`; the stream API always writes `chunked=true`. A single-frame plaintext MUST be shorter than 1 MiB: the Cipher decoder rejects a single-frame body (after the MAC) longer than `12 + (2^20 − 1) + 16` bytes, and one shorter than `12 + 16` bytes (tamper, because the MAC has verified).

### Stream decoder state machine

The decoder of a `chunked=true` body MUST follow these states. It runs only after the header MAC has verified, so the key is right and every failure is tamper.

```
ReadBase   read 12 bytes                          → ReadLen     (EOF: tamper)
ReadLen    read u32 len                            → ReadFrame   (len == 0 before the first frame, or EOF: tamper)
ReadFrame  check 16 ≤ len ≤ 65552, read len bytes  → PeekNext    (bound fails or EOF: tamper)
PeekNext   read u32 next                           → OpenFinal if next == 0, else OpenMid   (EOF: tamper)
OpenMid    require len == 65552, open (i, final=0), write → i += 1, len = next, ReadFrame
OpenFinal  require i == 0 or len ≥ 17, open (i, final=1), write → CheckEOF
CheckEOF   require the end of input                → done        (more bytes: tamper)
```

A truncation at a chunk boundary fails: the last remaining frame was sealed with `final=0`, so with a forged terminator it does not open as `final=1`. Without a terminator, the input ends in `PeekNext`. A swapped, repeated, or removed frame fails its GCM tag (the index is in the nonce and the AAD). The decoder authenticates each chunk before it writes the chunk. A stream writer cannot take back written bytes, so the caller MUST discard all output when the decoder fails.

## Decryption Order

1. Parse the prefix and the header JSON; apply §Header rules (parse error).
2. Read the 32-byte header MAC (the file ends: parse error).
3. Get the file key: Argon2id (method 3), the policy key (method 5), or the first CEK that a recipient block gives (method 2, §Recipient trial). No block opens: not a recipient.
4. Verify the header MAC with the file key (constant time). Failure: method 3 → wrong password; methods 2 and 5 → tamper.
5. Derive `payload_key` and decrypt the body. Any failure → tamper.

Nothing after the header MAC is read, and no plaintext is written, before step 4 succeeds.

### Output path

The sender writes `original_filename`, and the header MAC does not limit it: the sender computes the MAC. Even a safe base name is harmful as an output name (a dotfile such as `.zshenv` next to the input, a Windows device name, or the name of another file). A decryptor:

1. MUST NOT use `original_filename` as any part of a path. It MAY show it, quoted;
2. without an explicit output path, MUST derive the output path from the input path only: the input path without `.mdstn`, else the input path plus `.decrypted`;
3. without an explicit output path, MUST NOT replace an existing file unless the user asks for it. The check and the publication are one atomic step where the file system allows it;
4. MUST refuse an output path that is the same file as the input, in every case.

The Cipher CLI publishes with a no-replace rename (`renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS), else a hard link, else an `O_CREAT|O_EXCL` placeholder at the final name and a rename over it. The same-file and directory checks run by path before the work starts, and the output is published by path after it: an attacker who can swap a directory in between already has write access to that directory, and can change the input or the output anyway. `encrypt` and `backup` follow the same rules: `encrypt` never replaces `<file>.mdstn` without `--force`, and `backup` never replaces a file. No Cipher output (`decrypt`, `encrypt`, `keys export`, `backup`, the SDK, MCP), explicit or derived, with or without `--force`, may write into a folder of the key database: its configured folder, the folder of the resolved file when the database path is a symlink, or a folder that holds a hard link to it. SQLite replays a valid `<db>-journal` into the database at the next open, so a decrypted file at that name could rewrite the key store. The rule is by folder, not by name, because a file system can fold names (case, Unicode normalization) in ways that a name rule does not copy. A database given as a DSN (`file:…?…`, with `%XX` escapes) is decoded to the file that the driver opens for this rule. `--force` allows the derived path to replace a file. An explicit `-o PATH` is the user's choice and replaces a file at `PATH`, except the input.

### Recipient trial

1. Decode all blocks (a bad block is a parse error).
2. List the usable X25519 private keys: not expired, the default key first, then the other keys by use (the most used first).
3. For each key, and for each block in header order: compute `R_pub` from the private key, derive `kek`, and open `wrapped_cek`. The first block that opens gives the CEK. The decryptor does NOT try further blocks when the MAC then fails: a block that opens and a MAC that fails is an attack (tamper).
4. If no block opens with any key: not a recipient (exit 3). If a local key could not be unlocked (for example, no passphrase), the decryptor reports that error instead, because that key can be the recipient.

Cost: one private-key unlock per local key (Argon2id, or the session cache), and per (key, block) pair one X25519 operation, one HKDF, and one GCM open of 48 bytes.

## Error Classes

| Exit | Class (Go) | Raised when |
|---|---|---|
| 0 | — | success |
| 1 | parse/usage | §Header rules (unsupported version or method, strict base64, …), the file ends inside the header MAC, I/O errors, method 5 in the CLI |
| 2 | `ErrHeaderAuthFailed` | methods 2 and 5: the header MAC fails; any body failure after a good MAC (GCM, length bound, terminator, truncation, trailing bytes, empty final frame, single-frame size) |
| 3 | `ErrNotARecipient` | method 2: no recipient block opens with a usable local key |
| 4 | `ErrWrongPassword` | method 3: the header MAC fails |

Container decoding stops at the four classes above. The CLI's key-directory commands
(`keys publish`, `keys unpublish`) add two classes of their own for hosted-directory
server responses, mapped in `cmd/exit.go`: `ErrKDConflict` (exit 5, binding-state
rejection) and `ErrKDIntegrity` (exit 6, response signature/key-id/key-type failure).
They never apply to container bytes.

**Damaged recipient block (exit 3).** A damaged `wrapped_cek` (or a damaged `ephemeral_pub_key` or `nonce` that still decodes to the right length) cannot be told apart from a block for another key, because blocks name no recipient. When the damaged block is the only block that the local key could open, the result is not a recipient (exit 3), not exit 2.

**Method-3 ambiguity (exit 4).** A wrong password and a damaged header, salt, or header MAC fail the same check. The decryptor reports "wrong file password, or the file is damaged" (exit 4). After the MAC verifies, the password is proven, so a damaged body is always tamper (exit 2).

## Tamper Contract (normative)

A conforming decryptor MUST refuse every mutation below with the class shown, and MUST NOT publish plaintext. `internal/adapters/crypto/aad_tamper_test.go` runs every row on the committed vectors; the negative fixtures (§Test Vectors) pin the rows that need new bytes.

| Mutation | Result |
|---|---|
| A header byte, the header still parses (method 5) | exit 2 (MAC) |
| A header byte, the header still parses (method 2) | exit 2 (block opens, MAC fails) or exit 3 (the block no longer opens) |
| A header byte, the header still parses (method 3) | exit 4 (MAC) |
| A header byte, the header does not parse | exit 1 |
| Version byte to any value other than `0x03` | exit 1 "unsupported version" |
| A header MAC byte | methods 2 and 5: exit 2; method 3: exit 4 |
| File ends inside the header MAC | exit 1 |
| Single frame: nonce, ciphertext, or tag bit flip; body < 28 bytes; trailing byte | exit 2 |
| Stream: base nonce or any frame bit flip | exit 2 |
| Swap, repeat, or remove a frame (frame 0 included) | exit 2 |
| Forged length < 16 or > 65552 | exit 2, no large allocation |
| Truncate at a chunk boundary + terminator, without terminator, or inside a frame | exit 2 |
| An empty final frame after a full frame | exit 2 |
| Bytes after the terminator | exit 2 |
| Two blocks that wrap different CEKs (MAC under one of them) | the MAC key holder decrypts; the other recipient: exit 2 |
| CR/LF or non-zero padding bits in a base64 value | exit 1 |
| `original_filename` that is `.` or `..`, or holds a path separator, `:`, a control character, or an invisible character | exit 1 |
| A number with a fraction, an exponent, a sign, or above 2^53 − 1; `NaN`; a lone surrogate; nesting deeper than 8 | exit 1 |

In every failure row, the output path has no file. Method 5 has the same classes; the Cipher CLI does not decrypt method 5 (exit 1).

## Recovery Keys and Backup Bundle

### X25519 key from a recovery phrase

Every X25519 key pair in Cipher is derived from a 24-word BIP39 English mnemonic:

```
seed       = PBKDF2-HMAC-SHA512(password=NFKD(mnemonic), salt="mnemonic", iterations=2048, dkLen=64)
scalar     = HKDF-SHA256(ikm=seed, salt=32 zero bytes, info="cipher-x25519-v1", L=32)
public_key = X25519(scalar, 9)
```

The words are separated by one ASCII space. The raw 32-byte scalar is the canonical private key form (Web Crypto's PKCS#8 encoding ends with it). Anyone with the 24 words can derive the same key pair with any tool that implements this path.

### Key-passphrase wrapping (key at rest)

```
kek                 = Argon2id(key_passphrase, salt(16), m=65536 KiB, t=3, p=4, L=32)
wrapped_private_key = nonce(12) || AES-256-GCM(kek, nonce, scalar, aad="mdstn-wrapped-key:" + key_id)   # 60 bytes
```

The AAD binds the blob to its key ID, so a blob cannot move to another key.

### Key-backup bundle (optional)

A portable JSON artifact for offline key unwrapping without the recovery phrase:

```json
{
  "key_id": "<16-hex-char key id (= hex(SHA-256(public_key))[0:16])>",
  "public_key": "<base64-32-bytes>",
  "wrapped_private_key": "<base64-60-bytes>",
  "argon2id_salt": "<base64-16-bytes>",
  "kdf": {"m": 65536, "t": 3, "p": 4, "len": 32},
  "type": "x25519"
}
```

`key_id` is normative (it is in the AAD); a bundle without it is rejected. The browser assembles the bundle from data the server already holds; no plaintext key or passphrase reaches the server.

## Test Vectors

Normative vectors are committed in `internal/testdata/vectors.json`, with one `.mdstn` fixture per entry (`mdstn_file`, relative to `internal/testdata/`). A conforming implementation MUST decrypt every `vectors` entry to its plaintext and MUST refuse every `negative` entry with its `expect` class.

Members of an entry:

| Member | Meaning |
|---|---|
| `name`, `description`, `method`, `mdstn_file` | identity of the entry; `method` is the method byte |
| `container_version`, `chunked` | `vectors` only: version byte (3) and framing |
| `expect` | `negative` only: `parse` (exit 1), `tamper` (2), `not_a_recipient` (3), `wrong_password` (4) |
| `plaintext_b64` | the plaintext, base64 |
| `plaintext_rule`, `plaintext_len`, `plaintext_sha256` | stream vectors instead of `plaintext_b64`: `byte[i] = i mod 251` for `0 ≤ i < plaintext_len`; check the SHA-256 (hex) |
| `file_password` | method 3 |
| `recovery_phrase`, `recipient_public_key` | method 2: derive the key pair and check the public key |
| `bundle`, `key_passphrase` | method 2: unwrap the private key from the bundle |
| `shared_key_b64` | method 5: the 32-byte policy key |

`vectors` covers:

1. Every method × framing: `x25519-single`, `x25519-single-bundle`, `x25519-multi` (the key opens block 2, so the trial order is exercised), `passphrase`, `sharedkey`, each single frame and as a stream (suffix `-chunked`: 3 full 64 KiB chunks and 5 bytes).
2. `x25519-multi-16`: 16 recipient blocks (header size).
3. Stream edge lengths 0, 1, 65535, 65536, 65537, and 131072 bytes, for method 3 (`passphrase-len-N`) and method 2 with one block (`x25519-single-len-N`).

`negative` covers:

| Name | Expect | Mutation |
|---|---|---|
| `truncated-at-boundary` | tamper | password stream cut after frame 2 of 4, with a new terminator |
| `frame-after-final` | tamper | frame 1 repeated after the final frame |
| `frame-0-removed` | tamper | stream without frame 0 |
| `empty-final-frame` | tamper | a full frame, then an authentic empty final frame |
| `two-cek` | tamper | two blocks wrap different CEKs; MAC under block 1's CEK; the body opens under both payload keys; decrypted as recipient 2 |
| `crlf-in-base64` | parse | `\r\n` inside the salt value; MAC and body valid |
| `noncanonical-base64-padding` | parse | salt with non-zero padding bits; MAC and body valid |
| `version-0x01`, `version-0x02` | parse | valid file with a retired version byte |
| `wrong-password` | wrong_password | stream decrypted with another password |
| `not-a-recipient` | not_a_recipient | file for recipient 1 decrypted with recipient 2's key |
| `bad-filename` | parse | `original_filename` is `"../x"`; MAC and body valid |
| `bidi-filename` | parse | `original_filename` holds U+202E (right-to-left override); MAC and body valid |
| `nan-in-header` | parse | an unknown member with the value `NaN`; MAC and body valid |

`TestVectorsConformance` (`internal/adapters/crypto/vectors_conformance_test.go`) fails if an entry does not behave as stated, if a method × framing has no vector, or if a required negative fixture is missing. `TestGenerateVectors` (`CIPHER_REGENERATE_VECTORS=1`) only adds new files and entries; the committed fixtures stay byte-identical.

## Pseudocode Reference

The blocks below are Python 3 with the `cryptography` package (≥ 44, for Argon2id). Together they form one program. They were run against every entry of `vectors.json` (record: `specs/002-qa-remediation/quickstart.md`).

### Common helpers

```python
import base64, binascii, hashlib, hmac, json, struct, unicodedata
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class ParseError(Exception): pass       # exit 1
class TamperError(Exception): pass      # exit 2 (ErrHeaderAuthFailed)
class NotARecipient(Exception): pass    # exit 3
class WrongPassword(Exception): pass    # exit 4

MAX_FRAME = 65536 + 16
MAX_SINGLE_BODY = 12 + (1 << 20) - 1 + 16
FORBIDDEN = ("key_id", "recipient_key_id", "ephemeral_pub_key", "nonce", "encrypted_data", "fingerprint_hint")

def b64(s, size=None):
    """Strict base64 (§Strict base64)."""
    if not isinstance(s, str):
        raise ParseError("expected a base64 string")
    try:
        raw = base64.b64decode(s, validate=True)          # rejects CR, LF, and other characters
    except (binascii.Error, ValueError) as e:
        raise ParseError(f"invalid base64: {e}")
    if base64.b64encode(raw).decode() != s:
        raise ParseError("non-canonical base64")          # padding bits or padding
    if size is not None and len(raw) != size:
        raise ParseError(f"expected {size} bytes, got {len(raw)}")
    return raw

def no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ParseError(f"duplicate member {k!r}")
        obj[k] = v
    return obj

MAX_DEPTH = 8
MAX_INT = 2**53 - 1

def reject_constant(name):
    raise ParseError(f"{name} is not JSON")              # NaN, Infinity, -Infinity

def reject_float(text):
    raise ParseError(f"number {text} is not an integer")  # any fraction or exponent

def checked_int(text):
    if text.startswith("-"):
        raise ParseError(f"number {text} has a sign")     # "-0" included
    n = int(text)
    if n < 0 or n > MAX_INT:
        raise ParseError(f"number {text} is outside [0, 2^53 - 1]")
    return n

def check_json_value(v, depth=0):
    """§JSON rules: nesting depth and Unicode scalar values."""
    if isinstance(v, (dict, list)):
        if depth + 1 > MAX_DEPTH:
            raise ParseError(f"nesting deeper than {MAX_DEPTH} levels")
        items = list(v.items()) if isinstance(v, dict) else [(None, x) for x in v]
        for k, x in items:
            if k is not None:
                check_json_value(k, depth + 1)
            check_json_value(x, depth + 1)
    elif isinstance(v, str):
        try:
            v.encode("utf-8")                             # fails on a lone surrogate
        except UnicodeEncodeError:
            raise ParseError("string contains a lone surrogate")

def load_header_json(text):
    try:
        h = json.loads(text, object_pairs_hook=no_duplicates, parse_constant=reject_constant,
                       parse_float=reject_float, parse_int=checked_int)
    except (ValueError, RecursionError) as e:          # ParseError above is not a ValueError
        raise ParseError(f"header JSON: {e}")
    check_json_value(h)
    return h

def is_safe_base_name(name):
    """§Header JSON: original_filename. "" means no name."""
    if name == "":
        return True
    raw = name.encode("utf-8", "strict") if isinstance(name, str) else b""
    return (isinstance(name, str) and 1 <= len(raw) <= 255 and name not in (".", "..")
            and not any(c in name for c in "/\\:") and not any(is_control_or_bidi(ord(c)) for c in name))

INVISIBLE = [(0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001), (0xE0020, 0xE007F)]   # §Header JSON: Cf, Zl, Zp (Unicode 17), frozen

def is_control_or_bidi(cp):
    """C0/C1 controls and the frozen invisible-character list."""
    return cp < 0x20 or 0x7F <= cp <= 0x9F or any(lo <= cp <= hi for lo, hi in INVISIBLE)

def hkdf_sha256(ikm, salt, info, length=32):
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)

def x25519_public(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()

def x25519_shared(priv, pub):
    shared = X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))
    if shared == bytes(32):
        raise ValueError("all-zero shared secret")
    return shared

def argon2id(secret, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(secret)

def derive_x25519_from_phrase(phrase):
    words = unicodedata.normalize("NFKD", " ".join(phrase.split()))
    seed = hashlib.pbkdf2_hmac("sha512", words.encode(), b"mnemonic", 2048, 64)
    priv = hkdf_sha256(seed, bytes(32), b"cipher-x25519-v1")
    return x25519_public(priv), priv

def unwrap_bundle(bundle, key_passphrase):
    kek = argon2id(key_passphrase.encode(), b64(bundle["argon2id_salt"], 16))
    wrapped = b64(bundle["wrapped_private_key"])
    priv = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], b"mdstn-wrapped-key:" + bundle["key_id"].encode())
    if x25519_public(priv) != b64(bundle["public_key"], 32):
        raise ValueError("bundle public key does not match")
    return priv

P = 2**255 - 19

def is_canonical_public_key(pub):
    """§Canonical public keys: an encryptor checks every recipient key."""
    if len(pub) != 32 or pub[31] & 0x80 or int.from_bytes(pub, "little") >= P:
        return False
    try:
        x25519_shared(X25519PrivateKey.generate().private_bytes_raw(), pub)
    except ValueError:
        return False                                      # low-order point
    return True
```

### Header

```python
def is_integer(x):
    return not isinstance(x, bool) and (isinstance(x, int) or (isinstance(x, float) and x.is_integer()))

def parse_header(mdfile):
    """Returns (method, header, header_aad, header_mac, frames)."""
    if len(mdfile) < 8 or mdfile[0:4] != b"MDST":
        raise ParseError("invalid magic")
    if mdfile[4] != 0x03:
        raise ParseError(f"unsupported version: {mdfile[4]}")   # 0x01 and 0x02 are retired
    method = mdfile[5]
    if method not in (2, 3, 5):
        raise ParseError(f"unsupported method: {method}")
    end = 8 + struct.unpack(">H", mdfile[6:8])[0]
    if len(mdfile) < end + 32:
        raise ParseError("file ends inside the header or the header MAC")
    try:
        text = mdfile[8:end].decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseError(f"header JSON: {e}")
    h = load_header_json(text)
    if not isinstance(h, dict) or not isinstance(h.get("chunked"), bool):
        raise ParseError("missing chunked member")
    for k in FORBIDDEN:
        if k in h:
            raise ParseError(f"retired member {k!r}")
    name = h.get("original_filename", "")
    if not isinstance(name, str) or not is_safe_base_name(name):
        raise ParseError("original_filename must be a safe base name")
    if "encrypted_at" in h and not is_integer(h["encrypted_at"]):
        raise ParseError("encrypted_at must be an integer")
    if method == 2:
        blocks = h.get("recipients")
        if not isinstance(blocks, list) or not 1 <= len(blocks) <= 16:
            raise ParseError("need 1 to 16 recipient blocks")
        for b in blocks:
            if not isinstance(b, dict) or "fingerprint_hint" in b:
                raise ParseError("bad recipient block")
            b64(b.get("ephemeral_pub_key"), 32); b64(b.get("nonce"), 12); b64(b.get("wrapped_cek"), 48)
    elif method == 3:
        params = [h.get(k) for k in ("m", "t", "p")]
        if h.get("kdf") != "argon2id" or not all(is_integer(x) for x in params) or params != [65536, 3, 4]:
            raise ParseError("only kdf=argon2id, m=65536, t=3, p=4")
        b64(h.get("salt"), 16)
    elif not isinstance(h.get("policy_id"), str) or not h["policy_id"]:
        raise ParseError("policy_id required")
    return method, h, mdfile[:end], mdfile[end:end + 32], mdfile[end + 32:]
```

### File key and header MAC

```python
def cek_from_blocks(header, private_keys):
    """Method 2: trial decryption. private_keys in trial order (default key first)."""
    blocks = [(b64(b["ephemeral_pub_key"]), b64(b["nonce"]), b64(b["wrapped_cek"])) for b in header["recipients"]]
    for priv in private_keys:
        r_pub = x25519_public(priv)
        for eph, nonce, wrapped in blocks:
            try:
                kek = hkdf_sha256(x25519_shared(priv, eph), eph + r_pub, b"mdstn-cipher/v2/wrap")
                return AESGCM(kek).decrypt(nonce, wrapped, b"mdstn-cipher/v2/wrap-cek")
            except (InvalidTag, ValueError):
                continue
    raise NotARecipient()   # also for a damaged block: blocks name no recipient

def verify_header_mac(file_key, header_aad, header_mac):
    mac_key = hkdf_sha256(file_key, None, b"mdstn-cipher/v2/header-mac")
    want = hmac.new(mac_key, header_aad, hashlib.sha256).digest()
    return hmac.compare_digest(want, header_mac)

def payload_key(file_key):
    return hkdf_sha256(file_key, None, b"mdstn-cipher/v2/payload")
```

### Body

```python
def decrypt_single_frame(key, body, header_aad):
    """chunked=false: nonce(12) || ciphertext+tag."""
    if not 12 + 16 <= len(body) <= MAX_SINGLE_BODY:
        raise TamperError("single-frame body size")
    try:
        return AESGCM(key).decrypt(body[:12], body[12:], header_aad)
    except InvalidTag:
        raise TamperError("single frame")

def chunk_nonce(base, i):
    return base[:4] + (int.from_bytes(base[4:], "big") ^ i).to_bytes(8, "big")

def decrypt_stream(key, body, header_aad):
    """chunked=true: base(12) || [u32 len | ct]+ || u32(0) || EOF (§Stream decoder state machine)."""
    aead = AESGCM(key)

    def read_u32(at):
        if at + 4 > len(body):
            raise TamperError("stream truncated")
        return int.from_bytes(body[at:at + 4], "big")

    if len(body) < 12:
        raise TamperError("no base nonce")
    base = body[:12]
    n, pos = read_u32(12), 16
    if n == 0:
        raise TamperError("a stream has at least one frame")
    out, i = bytearray(), 0
    while True:
        if n < 16 or n > MAX_FRAME:
            raise TamperError(f"chunk {i}: length bound")
        ct = body[pos:pos + n]
        if len(ct) != n:
            raise TamperError(f"chunk {i}: truncated")
        pos += n
        nxt = read_u32(pos); pos += 4
        final = nxt == 0
        if not final and n != MAX_FRAME:
            raise TamperError(f"chunk {i}: a non-final chunk holds 65536 bytes")
        if final and i > 0 and n == 16:
            raise TamperError(f"chunk {i}: empty final frame after a full frame")
        aad = header_aad + i.to_bytes(8, "big") + (b"\x01" if final else b"\x00")
        try:
            out += aead.decrypt(chunk_nonce(base, i), ct, aad)
        except InvalidTag:
            raise TamperError(f"chunk {i}")
        if final:
            if pos != len(body):
                raise TamperError("data after the terminator")
            return bytes(out)
        i, n = i + 1, nxt
```

### Decrypt a file

```python
def decrypt(mdfile, file_password=None, private_keys=(), shared_key=None):
    """Returns the plaintext, or raises ParseError / TamperError / NotARecipient / WrongPassword."""
    method, header, header_aad, header_mac, body = parse_header(mdfile)
    if method == 3:
        file_key = argon2id(file_password.encode(), b64(header["salt"], 16))
    elif method == 2:
        file_key = cek_from_blocks(header, list(private_keys))
    else:
        file_key = shared_key                             # method 5: the policy key
    if not verify_header_mac(file_key, header_aad, header_mac):
        if method == 3:
            raise WrongPassword("wrong file password, or the file is damaged")
        raise TamperError("header MAC")
    key = payload_key(file_key)
    if header["chunked"]:
        return decrypt_stream(key, body, header_aad)
    return decrypt_single_frame(key, body, header_aad)
```

To decrypt an entry: `decrypt(mdfile, file_password=v["file_password"])` for method 3; `decrypt(mdfile, private_keys=[derive_x25519_from_phrase(v["recovery_phrase"])[1]])` or `private_keys=[unwrap_bundle(v["bundle"], v["key_passphrase"])]` for method 2; `decrypt(mdfile, shared_key=b64(v["shared_key_b64"]))` for method 5.

## Governance — Format Freeze

1. **One format.** Container version `0x03` is the only format. Versions `0x01` and `0x02` are retired: a decoder rejects them with "unsupported version", and they MUST NOT get a new meaning.
2. **Freeze.** `0x03` freezes at the first release tag that ships it: `v0.3.0` (2026-11-08). From then on, the container layout, header JSON schema, method bytes (`0x02`, `0x03`, `0x05`), KDFs and their parameters, key schedule (header MAC, payload key), AAD rule, framing rules, canonical rules (keys, base64, final frame), and error classes are normative and MUST NOT change under `0x03`.
3. **Any semantic change after the freeze requires the next unused version byte** (`0x04`) with its own header schema: a new method byte, a new header member with required interpretation, a different AAD or MAC rule, different framing, or different KDF parameters. Readers MUST reject unknown versions with a clear error.
4. **Byte-exactness bar.** A conforming implementation MUST decrypt every `vectors` entry of `internal/testdata/vectors.json` to its plaintext, and MUST refuse every `negative` entry and every §Tamper Contract row with its class. Adding a vector is a governance event: the generator only adds files and entries, and the committed fixtures stay byte-identical.
5. **Error-exit parity** (normative for the reference decryptor; recommended for others): `0` ok · `1` parse/usage · `2` tamper/header-auth failure · `3` not-a-recipient · `4` wrong file password. The CLI's key-directory (CKD) commands add two classes for server responses (outside the container format): `5` binding conflict (publish/unpublish rejected on binding-state grounds; the local key store is unchanged) · `6` response integrity failure (signature, service key id, or key type checks failed; nothing was cached).

## Limitations

### Method 3 cannot tell a wrong password from a damaged header

See §Error Classes. After the header MAC verifies, every failure is tamper.

### A damaged recipient block reads as "not a recipient"

See §Error Classes. Blocks name no recipient, so a damaged block looks like a block for another key.

### No sender authentication

The format does not authenticate the sender. The header MAC commits the header to the file key: every recipient gets the same plaintext or an error. It does not prove who made the file. Anyone with a recipient's public key can make a file for that recipient. A recipient of a multi-recipient file knows the file key, so that recipient can make a new file for the other recipients with their recipient blocks unchanged. To prove the sender, sign the file or the plaintext outside this format.

### Method 5 (Shared Key) is non-recoverable

Method-5 files use a pre-derived AES-256 policy key. The sharing protocol (client-side ECDH between the sharer and the recipient) establishes this key; it is **not** derivable from the recipient's recovery phrase. Without the sharing infrastructure, a user needs the original policy key, preserved separately, to decrypt a method-5 file.

## References

- **BIP39**: Mnemonic code for generating deterministic keys.
- **NIST SP 800-38D**: Galois/Counter Mode (GCM).
- **RFC 2104**: HMAC.
- **RFC 4648**: Base16, Base32, and Base64 data encodings (§4, §3.5 canonical encoding).
- **RFC 5869**: HKDF.
- **RFC 7748**: Elliptic Curves for Security (X25519).
- **RFC 9106**: Argon2.
- **Hoang, Reyhanitabar, Rogaway, Vizár (2015)**: Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance (the STREAM construction).
- **age** (C2SP age specification): the X25519 recipient and the header MAC that this format follows.
- **Len, Grubbs, Ristenpart (2021)**: Partitioning Oracle Attacks (why the header MAC commits to the key).
