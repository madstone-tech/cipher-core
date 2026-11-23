package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeHeaderRejectsRetiredVersions checks FR-001: 0x01 and 0x02 are
// retired, and every version byte other than 0x03 fails with "unsupported
// version", even with a header that is valid under the 0x03 rules.
func TestDecodeHeaderRejectsRetiredVersions(t *testing.T) {
	fe := NewFileEncoder()
	for _, version := range []byte{0x00, 0x01, 0x02, 0x04, 0xff} {
		for _, header := range []map[string]any{validV2Password(), validV2Recipients(1)} {
			method := byte(3)
			if _, ok := header["recipients"]; ok {
				method = 2
			}
			_, err := fe.Decode(buildV2Container(t, version, method, header))
			if err == nil || !strings.Contains(err.Error(), "unsupported version") {
				t.Errorf("version %#x, method %d: err = %v, want unsupported version", version, method, err)
			}
		}
	}
	// 0x01 with a v1-shaped header (salt of 32 bytes, nonce member) too.
	v1 := map[string]any{"chunked": false, "method": "pbkdf2-aes256", "salt": b64(32), "nonce": nil, "encrypted_data": nil, "key_id": ""}
	if _, err := fe.Decode(buildV2Container(t, 0x01, 3, v1)); err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Errorf("v1 file: err = %v, want unsupported version", err)
	}
}

// nonCanonicalB64 returns s with a non-zero padding bit: s must end with "=",
// so its last data character carries unused low bits.
func nonCanonicalB64(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	end := strings.TrimRight(s, "=")
	if len(end) == len(s) {
		t.Fatalf("%q has no padding", s)
	}
	i := strings.IndexByte(alphabet, end[len(end)-1])
	return end[:len(end)-1] + string(alphabet[i|1]) + s[len(end):]
}

// TestHeaderBase64IsStrict checks FR-006: every base64 header value is
// strict RFC 4648 standard encoding with padding. CR, LF, and non-zero
// padding bits fail to parse (Go's decoder skips CR/LF and, without Strict,
// ignores padding bits).
func TestHeaderBase64IsStrict(t *testing.T) {
	fe := NewFileEncoder()
	if got := nonCanonicalB64(t, b64(16)); bytes.Equal(mustB64(t, got), mustB64(t, b64(16))) == false {
		t.Fatalf("lenient decode of %q differs; the test needs the same bytes", got)
	}

	type field struct {
		name   string
		header func(value string) map[string]any
		value  string
	}
	block := func(member string) func(string) map[string]any {
		return func(value string) map[string]any {
			h := validV2Recipients(1)
			h["recipients"].([]any)[0].(map[string]any)[member] = value
			return h
		}
	}
	fields := []field{
		{"salt", func(v string) map[string]any { h := validV2Password(); h["salt"] = v; return h }, b64(16)},
		{"ephemeral_pub_key", block("ephemeral_pub_key"), b64(32)},
		{"nonce", block("nonce"), b64(12)},
		{"wrapped_cek", block("wrapped_cek"), b64(48)},
	}
	for _, f := range fields {
		method := byte(2)
		if f.name == "salt" {
			method = 3
		}
		if _, err := fe.Decode(buildV2Container(t, formatV2, method, f.header(f.value))); err != nil {
			t.Fatalf("%s control: %v", f.name, err)
		}
		bad := map[string]string{
			"LF inside":       f.value[:4] + "\n" + f.value[4:],
			"CR inside":       f.value[:4] + "\r" + f.value[4:],
			"CRLF at the end": f.value + "\r\n",
		}
		if strings.HasSuffix(f.value, "=") {
			bad["non-zero padding bits"] = nonCanonicalB64(t, f.value)
		}
		for name, v := range bad {
			if _, err := fe.Decode(buildV2Container(t, formatV2, method, f.header(v))); err == nil {
				t.Errorf("%s with %s: decoded; want a parse error", f.name, name)
			}
		}
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestStreamRejectsEmptyFinalFrameAfterFullFrame checks FR-005 (V2-4): with
// more than one frame, the final frame holds at least one plaintext byte. A
// full non-final frame followed by an empty final frame is a second encoding
// of the same plaintext and fails with the tamper class. One empty final
// frame (the empty plaintext) stays valid.
func TestStreamRejectsEmptyFinalFrameAfterFullFrame(t *testing.T) {
	key := randomKey(t)
	aad := []byte("header-aad")
	base := bytes.Repeat([]byte{0x07}, aesGCMNonceSize)

	full := sealFrameV2(t, key, base, aad, 0, false, patternPlaintext(streamChunkSize))
	empty := sealFrameV2(t, key, base, aad, 1, true, nil)
	out, err := decryptV2(key, aad, joinV2(base, true, full, empty))
	requireChunkAuthError(t, err)
	if len(out) > streamChunkSize {
		t.Errorf("%d bytes written", len(out))
	}

	if got, err := decryptV2(key, aad, joinV2(base, true, sealFrameV2(t, key, base, aad, 0, true, nil))); err != nil || len(got) != 0 {
		t.Errorf("empty plaintext (one empty final frame): %d bytes, err %v", len(got), err)
	}
	one := sealFrameV2(t, key, base, aad, 1, true, []byte{0x42})
	if got, err := decryptV2(key, aad, joinV2(base, true, full, one)); err != nil || len(got) != streamChunkSize+1 {
		t.Errorf("full frame + 1-byte final frame: %d bytes, err %v", len(got), err)
	}
}
