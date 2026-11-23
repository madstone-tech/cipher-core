package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/tyler-smith/go-bip39"
)

// vectorsDir is the canonical test-vector directory (internal/testdata).
const vectorsDir = "../../testdata"

// chunkedVectorLen is the plaintext length of the method × framing stream
// vectors: three full 64 KiB chunks and a final chunk of 5 bytes.
const chunkedVectorLen = 3*streamChunkSize + 5

// streamEdgeLengths are the plaintext lengths of the stream edge vectors
// (FR-007): empty, one byte, one chunk minus one, exactly one and two chunks,
// and one chunk plus one.
var streamEdgeLengths = []int{0, 1, 65535, 65536, 65537, 131072}

// chunkedPlaintextRule documents the plaintext of the stream vectors in
// vectors.json; patternPlaintext implements it.
const chunkedPlaintextRule = "byte[i] = i mod 251"

// patternPlaintext returns n bytes with byte[i] = i mod 251 (chunkedPlaintextRule).
// The stream vectors carry this rule, the length, and the SHA-256 instead of
// a large base64 plaintext.
func patternPlaintext(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// Failure classes of the negative fixtures (vectors.json "expect"), with the
// exit code of docs/format-spec.md §Error classes.
const (
	expectParse         = "parse"           // exit 1
	expectTamper        = "tamper"          // exit 2, ErrHeaderAuthFailed
	expectNotARecipient = "not_a_recipient" // exit 3, ErrNotARecipient
	expectWrongPassword = "wrong_password"  // exit 4, ErrWrongPassword
)

// vectorArrays are the entry arrays of vectors.json: positive vectors, and
// negative fixtures that MUST fail with their "expect" class.
var vectorArrays = []string{"vectors", "negative"}

// vectorSet adds entries to testdata/vectors.json without changing existing
// ones. Committed fixtures are normative (docs/format-spec.md §Governance), so
// the generator never rewrites a fixture file or an existing entry: it writes
// a fixture only if the file does not exist, and appends an entry only if its
// name is new in its array. Existing entries are kept as raw JSON, in their
// order.
type vectorSet struct {
	t        *testing.T
	top      map[string]json.RawMessage
	entries  map[string][]json.RawMessage
	existing map[string]bool // array + "/" + entry name already in vectors.json
	written  map[string]bool // fixture files written by this run
	added    []string
}

func loadVectorSet(t *testing.T) *vectorSet {
	t.Helper()
	vs := &vectorSet{
		t:        t,
		top:      map[string]json.RawMessage{},
		entries:  map[string][]json.RawMessage{},
		existing: map[string]bool{},
		written:  map[string]bool{},
	}
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "vectors.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return vs
	}
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	if err := json.Unmarshal(raw, &vs.top); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	for _, array := range vectorArrays {
		if _, ok := vs.top[array]; !ok {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(vs.top[array], &entries); err != nil {
			t.Fatalf("parse vectors.json %s: %v", array, err)
		}
		for _, e := range entries {
			var head struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(e, &head); err != nil {
				t.Fatalf("parse %s entry: %v", array, err)
			}
			vs.existing[array+"/"+head.Name] = true
		}
		vs.entries[array] = entries
	}
	return vs
}

// fixture writes data to testdata/name only if the file does not exist.
func (vs *vectorSet) fixture(name string, data []byte) {
	vs.t.Helper()
	path := filepath.Join(vectorsDir, name)
	_, err := os.Stat(path)
	if err == nil {
		return
	}
	if !errors.Is(err, fs.ErrNotExist) {
		vs.t.Fatalf("stat %s: %v", name, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		vs.t.Fatalf("write %s: %v", name, err)
	}
	vs.written[name] = true
}

// add appends entry to array unless an entry with its name exists there. An
// existing entry must keep its fixture, and a new entry must have a fixture
// from this run: otherwise the entry and the file bytes would not match.
func (vs *vectorSet) add(array string, entry map[string]any) {
	vs.t.Helper()
	name, nameOK := entry["name"].(string)
	file, fileOK := entry["mdstn_file"].(string)
	if !nameOK || !fileOK || name == "" || file == "" {
		vs.t.Fatalf("vector entry needs name and mdstn_file: %v", entry)
	}
	key := array + "/" + name
	if vs.existing[key] {
		if vs.written[file] {
			vs.t.Fatalf("existing vector %q lost its fixture %s; restore it from git, do not regenerate it", name, file)
		}
		return
	}
	if !vs.written[file] {
		vs.t.Fatalf("new vector %q would reuse the existing fixture %s; give it a new file name", name, file)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		vs.t.Fatalf("marshal vector %q: %v", name, err)
	}
	vs.entries[array] = append(vs.entries[array], raw)
	vs.existing[key] = true
	vs.added = append(vs.added, key)
}

func (vs *vectorSet) save() {
	vs.t.Helper()
	vs.top["version"] = json.RawMessage("3")
	vs.top["comment"] = json.RawMessage(`"Normative test vectors for the .mdstn container format (version byte 0x03). Every vectors entry decrypts to its plaintext; every negative entry fails with its expect class. Generated by go test -run TestGenerateVectors"`)
	for _, array := range vectorArrays {
		entries, err := json.Marshal(vs.entries[array])
		if err != nil {
			vs.t.Fatalf("marshal %s: %v", array, err)
		}
		vs.top[array] = entries
	}
	out, err := json.MarshalIndent(vs.top, "", "  ")
	if err != nil {
		vs.t.Fatalf("marshal vectors.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vectorsDir, "vectors.json"), append(out, '\n'), 0o644); err != nil {
		vs.t.Fatalf("write vectors.json: %v", err)
	}
	vs.t.Logf("vectors added: %v", vs.added)
}

// sealContainer returns header || header_mac || body for fileKey, with the
// body sealed by the payload key: nonce(12) || ct (chunked=false) or the
// stream (chunked=true).
func sealContainer(t *testing.T, engine *Engine, header, fileKey, plaintext []byte) []byte {
	t.Helper()
	mac, err := engine.HeaderMAC(fileKey, header)
	if err != nil {
		t.Fatal(err)
	}
	payloadKey, err := engine.DerivePayloadKey(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	out := bytes.NewBuffer(append(append([]byte{}, header...), mac...))
	file, err := NewFileEncoder().Decode(header)
	if err != nil {
		t.Fatalf("sealContainer: header does not decode: %v", err)
	}
	if !file.Chunked {
		ct, nonce, err := engine.EncryptAES(plaintext, payloadKey, header)
		if err != nil {
			t.Fatalf("EncryptAES body: %v", err)
		}
		return append(append(out.Bytes(), nonce...), ct...)
	}
	if err := engine.EncryptStream(context.Background(), bytes.NewReader(plaintext), out, payloadKey, header); err != nil {
		t.Fatalf("EncryptStream body: %v", err)
	}
	return out.Bytes()
}

// plaintextFields returns the plaintext members of a vector entry: inline
// base64 for the short plaintext of a single-frame vector, or the rule,
// length, and SHA-256 of the pattern plaintext of n bytes.
func plaintextFields(chunked bool, short []byte, n int) (map[string]any, []byte) {
	if !chunked {
		return map[string]any{"plaintext_b64": base64.StdEncoding.EncodeToString(short)}, short
	}
	pt := patternPlaintext(n)
	sum := sha256.Sum256(pt)
	return map[string]any{
		"plaintext_rule":   chunkedPlaintextRule,
		"plaintext_len":    len(pt),
		"plaintext_sha256": hex.EncodeToString(sum[:]),
	}, pt
}

func mergeFields(dst map[string]any, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// v2RecipientBlocks wraps cek to each public key.
func v2RecipientBlocks(t *testing.T, engine *Engine, cek []byte, pubs ...[]byte) []entities.RecipientBlock {
	t.Helper()
	blocks := make([]entities.RecipientBlock, 0, len(pubs))
	for i, pub := range pubs {
		eph, nonce, wrapped, err := engine.WrapCEK(cek, pub, []byte(entities.WrapCEKAAD))
		if err != nil {
			t.Fatalf("WrapCEK(%d): %v", i, err)
		}
		blocks = append(blocks, entities.RecipientBlock{
			EphemeralPubKey: base64.StdEncoding.EncodeToString(eph),
			Nonce:           base64.StdEncoding.EncodeToString(nonce),
			WrappedCEK:      base64.StdEncoding.EncodeToString(wrapped),
		})
	}
	return blocks
}

// rawHeader returns magic | 0x03 | method | u16be(len) | headerJSON for a
// header JSON that the encoder cannot write (negative fixtures).
func rawHeader(method byte, headerJSON string) []byte {
	out := append([]byte(mdstMagic), entities.FormatVersion, method)
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerJSON))) // #nosec G115 -- small test header
	return append(out, headerJSON...)
}

// splitStreamContainer splits a stream container into head (header, header
// MAC, base nonce) and its frames (u32be(len) || ct), without the terminator.
func splitStreamContainer(t *testing.T, container []byte) (head []byte, frames [][]byte) {
	t.Helper()
	_, _, offset, err := NewFileEncoder().DecodeWithOffset(container)
	if err != nil {
		t.Fatal(err)
	}
	p := int(offset) + entities.HeaderMACSize + aesGCMNonceSize
	head = container[:p]
	for {
		n := int(binary.BigEndian.Uint32(container[p : p+4]))
		if n == 0 {
			if p+4 != len(container) {
				t.Fatalf("%d bytes after the terminator", len(container)-p-4)
			}
			return head, frames
		}
		frames = append(frames, container[p:p+4+n])
		p += 4 + n
	}
}

// joinStreamContainer returns head || frames || (terminator if term).
func joinStreamContainer(head []byte, term bool, frames ...[]byte) []byte {
	out := append([]byte{}, head...)
	for _, f := range frames {
		out = append(out, f...)
	}
	if term {
		out = append(out, 0, 0, 0, 0)
	}
	return out
}

// TestGenerateVectors produces committed test vectors for the reference decryptor.
// Run: CIPHER_REGENERATE_VECTORS=1 go test -run TestGenerateVectors -v ./internal/adapters/crypto/
// Then commit the generated files in testdata/.
//
// Guarded because regeneration rewrites the conformance bar. Left ungated, a
// plain `go test ./...` silently replaced the vectors with whatever the current
// code produced, so drift could never be detected — see
// TestVectorsConformance, which reads these vectors instead of writing them.
//
// The run is append-only (vectorSet): committed fixtures and entries stay
// byte-identical, and only entries with a new name are added. Adding a
// vector is a format-governance event (docs/format-spec.md §Governance).
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("CIPHER_REGENERATE_VECTORS") != "1" {
		t.Skip("set CIPHER_REGENERATE_VECTORS=1 to add new vectors to testdata/vectors.json")
	}

	vs := loadVectorSet(t)
	engine := NewEngine()
	kekProvider := NewArgon2idKEKProvider()
	encoder := NewFileEncoder()

	plaintext := []byte("The quick brown fox jumps over the lazy dog.")
	const filename = "test.txt"
	encryptedAt := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	const filePassword = "test-file-password-123!"

	// Key material. Recipient keys come from fixed BIP39 entropy.
	keyFromEntropy := func(seed func(i int) byte) (string, []byte) {
		e := make([]byte, 32)
		for i := range e {
			e[i] = seed(i)
		}
		mn, err := bip39.NewMnemonic(e)
		if err != nil {
			t.Fatalf("NewMnemonic: %v", err)
		}
		pub, _, err := DeriveX25519FromMnemonic(mn)
		if err != nil {
			t.Fatalf("DeriveX25519FromMnemonic: %v", err)
		}
		return mn, pub
	}
	mnemonic1, pub1 := keyFromEntropy(func(i int) byte { return byte(i) })
	mnemonic2, pub2 := keyFromEntropy(func(i int) byte { return byte(i + 1) })
	pubs16 := make([][]byte, 16)
	mnemonics16 := make([]string, 16)
	for k := range pubs16 {
		mnemonics16[k], pubs16[k] = keyFromEntropy(func(j int) byte { return byte(k+2) ^ byte(j) })
	}

	// Backup bundle of recipient 1 (key-at-rest wrap, Argon2id KEK).
	const keyPassphrase = "key-unlock-passphrase-456"
	const bundleKeyID = "test-key-id"
	_, priv1, err := DeriveX25519FromMnemonic(mnemonic1)
	if err != nil {
		t.Fatal(err)
	}
	kek, bundleSalt, err := engine.DeriveKeyArgon2id(keyPassphrase)
	if err != nil {
		t.Fatalf("DeriveKeyArgon2id: %v", err)
	}
	wrappedPriv1, err := kekProvider.WrapKey(priv1, kek, bundleKeyID)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	bundle := map[string]any{
		"key_id":              bundleKeyID,
		"public_key":          base64.StdEncoding.EncodeToString(pub1),
		"wrapped_private_key": base64.StdEncoding.EncodeToString(wrappedPriv1),
		"argon2id_salt":       base64.StdEncoding.EncodeToString(bundleSalt),
		"kdf":                 map[string]int{"m": 65536, "t": 3, "p": 4, "len": 32},
		"type":                "x25519",
	}

	passSalt := []byte("vector-salt-0016") // 16 bytes, deterministic
	passKey, err := engine.DeriveFileKeyArgon2id(filePassword, passSalt)
	if err != nil {
		t.Fatalf("DeriveFileKeyArgon2id: %v", err)
	}
	// Method 5: the policy key is fixed at the crypto layer (the sharing
	// protocol that makes it is out of scope for the container format).
	sharedKey := make([]byte, 32)
	for i := range sharedKey {
		sharedKey[i] = byte(0xA0 + i)
	}
	const policyID = "00000000-0000-4000-8000-000000000005"

	header := func(file *entities.EncryptedFile, chunked bool) []byte {
		file.Version = entities.FormatVersion
		file.Chunked = chunked
		file.OriginalFilename = filename
		file.EncryptedAt = encryptedAt
		h, err := encoder.EncodeHeader(file)
		if err != nil {
			t.Fatalf("EncodeHeader: %v", err)
		}
		return h
	}
	newCEK := func() []byte {
		cek, err := engine.GenerateAESKey()
		if err != nil {
			t.Fatal(err)
		}
		return cek
	}
	x25519File := func(cek []byte, pubs ...[]byte) *entities.EncryptedFile {
		return &entities.EncryptedFile{Method: entities.MethodX25519, Recipients: v2RecipientBlocks(t, engine, cek, pubs...)}
	}
	passFile := func() *entities.EncryptedFile {
		return &entities.EncryptedFile{Method: entities.MethodPassphrase, Salt: passSalt, KDF: entities.KDFArgon2id, KDFParams: entities.FileKDFParams}
	}
	entry := func(name string, method int, chunked bool, fixture, description string, fields ...map[string]any) map[string]any {
		e := map[string]any{
			"name":              name,
			"method":            method,
			"container_version": int(entities.FormatVersion),
			"chunked":           chunked,
			"mdstn_file":        fixture,
			"description":       description,
		}
		for _, f := range fields {
			mergeFields(e, f)
		}
		return e
	}
	phrase1 := map[string]any{"recovery_phrase": mnemonic1, "recipient_public_key": base64.StdEncoding.EncodeToString(pub1)}
	phrase2 := map[string]any{"recovery_phrase": mnemonic2, "recipient_public_key": base64.StdEncoding.EncodeToString(pub2)}
	password := map[string]any{"file_password": filePassword}
	shared := map[string]any{"shared_key_b64": base64.StdEncoding.EncodeToString(sharedKey)}

	// ── Every method × framing ──
	for _, chunked := range []bool{false, true} {
		suffix, fileSuffix, framing := "", "", "single frame"
		if chunked {
			suffix, fileSuffix, framing = "-chunked", "_chunked", "stream, 3 full 64 KiB chunks + 5 bytes"
		}
		ptFields, pt := plaintextFields(chunked, plaintext, chunkedVectorLen)

		cek := newCEK()
		fixture := "x25519_single" + fileSuffix + ".mdstn"
		vs.fixture(fixture, sealContainer(t, engine, header(x25519File(cek, pub1), chunked), cek, pt))
		vs.add("vectors", entry("x25519-single"+suffix, 2, chunked, fixture,
			"X25519, one recipient block; key from the recovery phrase; "+framing, phrase1, ptFields))
		vs.add("vectors", entry("x25519-single-bundle"+suffix, 2, chunked, fixture,
			"X25519, one recipient block; key unwrapped from the backup bundle; "+framing,
			map[string]any{"bundle": bundle, "key_passphrase": keyPassphrase}, ptFields))

		cek = newCEK()
		fixture = "x25519_multi" + fileSuffix + ".mdstn"
		vs.fixture(fixture, sealContainer(t, engine, header(x25519File(cek, pub1, pub2), chunked), cek, pt))
		vs.add("vectors", entry("x25519-multi"+suffix, 2, chunked, fixture,
			"X25519, two recipient blocks; the key opens block 2 (trial decryption); "+framing, phrase2, ptFields))

		fixture = "passphrase" + fileSuffix + ".mdstn"
		vs.fixture(fixture, sealContainer(t, engine, header(passFile(), chunked), passKey, pt))
		vs.add("vectors", entry("passphrase"+suffix, 3, chunked, fixture,
			"file password, Argon2id m=65536 t=3 p=4, 16-byte salt; "+framing, password, ptFields))

		fixture = "sharedkey" + fileSuffix + ".mdstn"
		vs.fixture(fixture, sealContainer(t, engine, header(&entities.EncryptedFile{Method: entities.MethodSharedKey, PolicyID: policyID}, chunked), sharedKey, pt))
		vs.add("vectors", entry("sharedkey"+suffix, 5, chunked, fixture,
			"shared key: the 32-byte policy key is given; "+framing, shared, ptFields))
	}

	// ── 16 recipient blocks (header size) ──
	cek16 := newCEK()
	vs.fixture("x25519_multi_16.mdstn", sealContainer(t, engine, header(x25519File(cek16, pubs16...), false), cek16, plaintext))
	vs.add("vectors", entry("x25519-multi-16", 2, false, "x25519_multi_16.mdstn",
		"X25519, 16 recipient blocks; the key opens block 1; single frame",
		map[string]any{"recovery_phrase": mnemonics16[0], "recipient_public_key": base64.StdEncoding.EncodeToString(pubs16[0])},
		map[string]any{"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext)}))

	// ── Stream edge lengths (FR-007), method 3 and method 2 with one block ──
	for _, n := range streamEdgeLengths {
		ptFields, pt := plaintextFields(true, nil, n)
		fixture := fmt.Sprintf("passphrase_len_%d.mdstn", n)
		vs.fixture(fixture, sealContainer(t, engine, header(passFile(), true), passKey, pt))
		vs.add("vectors", entry(fmt.Sprintf("passphrase-len-%d", n), 3, true, fixture,
			fmt.Sprintf("file password, stream of %d plaintext bytes", n), password, ptFields))

		cek := newCEK()
		fixture = fmt.Sprintf("x25519_single_len_%d.mdstn", n)
		vs.fixture(fixture, sealContainer(t, engine, header(x25519File(cek, pub1), true), cek, pt))
		vs.add("vectors", entry(fmt.Sprintf("x25519-single-len-%d", n), 2, true, fixture,
			fmt.Sprintf("X25519, one recipient block, stream of %d plaintext bytes", n), phrase1, ptFields))
	}

	// ── Negative fixtures: each MUST fail with its expect class ──
	negative := func(name, expect, fixture, description string, data []byte, method int, fields map[string]any) {
		vs.fixture(fixture, data)
		vs.add("negative", mergeFields(map[string]any{
			"name": name, "expect": expect, "method": method, "mdstn_file": fixture, "description": description,
		}, fields))
	}

	streamPT := patternPlaintext(chunkedVectorLen)
	stream := sealContainer(t, engine, header(passFile(), true), passKey, streamPT)
	head, frames := splitStreamContainer(t, stream)
	negative("truncated-at-boundary", expectTamper, "negative_truncated_at_boundary.mdstn",
		"password stream cut after frame 2 of 4, with a new terminator: frame 2 was sealed as non-final",
		joinStreamContainer(head, true, frames[:3]...), 3, password)
	negative("frame-after-final", expectTamper, "negative_frame_after_final.mdstn",
		"password stream with frame 1 repeated after the final frame 3",
		joinStreamContainer(head, true, append(append([][]byte{}, frames...), frames[1])...), 3, password)
	negative("frame-0-removed", expectTamper, "negative_frame_0_removed.mdstn",
		"password stream without frame 0",
		joinStreamContainer(head, true, frames[1:]...), 3, password)

	// A full non-final frame, then an empty final frame (both authentic).
	emptyHeader := header(passFile(), true)
	emptyFinal := sealContainer(t, engine, emptyHeader, passKey, nil)[:len(emptyHeader)+entities.HeaderMACSize]
	payloadKey, err := engine.DerivePayloadKey(passKey)
	if err != nil {
		t.Fatal(err)
	}
	base := bytes.Repeat([]byte{0x3c}, aesGCMNonceSize)
	emptyFinal = append(emptyFinal, base...)
	emptyFinal = append(emptyFinal, sealFrameV2(t, payloadKey, base, emptyHeader, 0, false, patternPlaintext(streamChunkSize))...)
	emptyFinal = append(emptyFinal, sealFrameV2(t, payloadKey, base, emptyHeader, 1, true, nil)...)
	emptyFinal = append(emptyFinal, 0, 0, 0, 0)
	negative("empty-final-frame", expectTamper, "negative_empty_final_frame.mdstn",
		"password stream: a full non-final frame, then an authentic empty final frame (a second encoding of 65536 bytes)",
		emptyFinal, 3, password)

	// V2-1: block 1 wraps CEK1 for recipient 1, block 2 wraps CEK2 for
	// recipient 2, the header MAC uses CEK1, and the single frame opens under
	// both payload keys (AES-GCM is not key committing).
	cekA, cekB := newCEK(), newCEK()
	twoCEKFile := &entities.EncryptedFile{Method: entities.MethodX25519, Recipients: append(
		v2RecipientBlocks(t, engine, cekA, pub1), v2RecipientBlocks(t, engine, cekB, pub2)...)}
	twoCEKHeader := header(twoCEKFile, false)
	macA, err := engine.HeaderMAC(cekA, twoCEKHeader)
	if err != nil {
		t.Fatal(err)
	}
	payloadA, err := engine.DerivePayloadKey(cekA)
	if err != nil {
		t.Fatal(err)
	}
	payloadB, err := engine.DerivePayloadKey(cekB)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5a}, aesGCMNonceSize)
	twoCEK := append(append(append(append([]byte{}, twoCEKHeader...), macA...), nonce...), gcmSalamander(t, payloadA, payloadB, nonce, twoCEKHeader)...)
	negative("two-cek", expectTamper, "negative_two_cek.mdstn",
		"two recipient blocks wrap different CEKs; the header MAC uses block 1's CEK and the body opens under both payload keys; recipient 2 unwraps block 2 and fails the header MAC",
		twoCEK, 2, phrase2)

	// CR/LF and non-canonical padding in a base64 header value. The header MAC
	// and the body are valid, so a lenient base64 decoder decrypts the file.
	saltB64 := base64.StdEncoding.EncodeToString(passSalt)
	lenientHeader := func(salt string) []byte {
		return rawHeader(3, `{"chunked":false,"encrypted_at":1793750400,"kdf":"argon2id","m":65536,"original_filename":"test.txt","p":4,"salt":"`+salt+`","t":3}`)
	}
	sealLenient := func(h []byte) []byte {
		mac, err := engine.HeaderMAC(passKey, h)
		if err != nil {
			t.Fatal(err)
		}
		ct, nonce, err := engine.EncryptAES(plaintext, payloadKey, h)
		if err != nil {
			t.Fatal(err)
		}
		return append(append(append(append([]byte{}, h...), mac...), nonce...), ct...)
	}
	negative("crlf-in-base64", expectParse, "negative_crlf_in_base64.mdstn",
		`password file whose salt value has "\r\n" inside; MAC and body are valid`,
		sealLenient(lenientHeader(saltB64[:8]+`\r\n`+saltB64[8:])), 3, password)
	negative("noncanonical-base64-padding", expectParse, "negative_noncanonical_base64.mdstn",
		"password file whose salt value has non-zero padding bits; MAC and body are valid",
		sealLenient(lenientHeader(nonCanonicalB64(t, saltB64))), 3, password)
	// Q1: a sender-chosen output path. Q5: JSON that a lax parser accepts.
	// Both have a valid header MAC and body, so only the header rules reject them.
	badNameHeader := rawHeader(3, `{"chunked":false,"encrypted_at":1793750400,"kdf":"argon2id","m":65536,"original_filename":"../x","p":4,"salt":"`+saltB64+`","t":3}`)
	negative("bad-filename", expectParse, "negative_bad_filename.mdstn",
		`password file whose original_filename is "../x" (not a safe base name); MAC and body are valid`,
		sealLenient(badNameHeader), 3, password)
	bidiHeader := rawHeader(3, `{"chunked":false,"encrypted_at":1793750400,"kdf":"argon2id","m":65536,"original_filename":"invoice\u202efdp.exe","p":4,"salt":"`+saltB64+`","t":3}`)
	negative("bidi-filename", expectParse, "negative_bidi_filename.mdstn",
		"password file whose original_filename holds U+202E (right-to-left override); MAC and body are valid",
		sealLenient(bidiHeader), 3, password)
	nanHeader := rawHeader(3, `{"chunked":false,"encrypted_at":1793750400,"kdf":"argon2id","m":65536,"original_filename":"test.txt","p":4,"salt":"`+saltB64+`","t":3,"x":NaN}`)
	negative("nan-in-header", expectParse, "negative_nan_in_header.mdstn",
		"password file with an unknown member whose value is NaN (not JSON); MAC and body are valid",
		sealLenient(nanHeader), 3, password)

	// Retired version bytes: a valid file with byte 4 changed.
	single := sealContainer(t, engine, header(passFile(), false), passKey, plaintext)
	for _, v := range []byte{0x01, 0x02} {
		retired := append([]byte{}, single...)
		retired[4] = v
		negative(fmt.Sprintf("version-0x%02x", v), expectParse, fmt.Sprintf("negative_version_%02x.mdstn", v),
			fmt.Sprintf("valid password file with version byte 0x%02x: unsupported version", v), retired, 3, password)
	}

	// Classes that need no new fixture bytes but a different key.
	wrong := sealContainer(t, engine, header(passFile(), true), passKey, patternPlaintext(2*streamChunkSize))
	negative("wrong-password", expectWrongPassword, "negative_wrong_password.mdstn",
		"password stream decrypted with a wrong password: the header MAC fails before the body",
		wrong, 3, map[string]any{"file_password": "not-the-password"})
	cekN := newCEK()
	negative("not-a-recipient", expectNotARecipient, "negative_not_a_recipient.mdstn",
		"X25519 file for recipient 1, decrypted with recipient 2's key: no block opens",
		sealContainer(t, engine, header(x25519File(cekN, pub1), false), cekN, plaintext), 2, phrase2)

	if strings.Contains(string(twoCEKHeader), "fingerprint_hint") {
		t.Fatal("generator wrote a retired member")
	}
	vs.save()
}
