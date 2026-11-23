package crypto

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// rawContainer builds a method-3 container header from raw JSON text, so a
// test can use JSON that encoding/json would not write.
func rawContainer(headerJSON string) []byte {
	out := append([]byte(mdstMagic), 0x03, 3)
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerJSON))) // #nosec G115 -- small test header
	return append(out, headerJSON...)
}

// passwordHeaderWith returns a valid method-3 header as JSON text with member
// key set to the raw JSON value raw.
func passwordHeaderWith(t *testing.T, key, raw string) string {
	t.Helper()
	h := validV2Password()
	delete(h, key)
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(b), "}") + `,"` + key + `":` + raw + `}`
}

// TestDecodeRejectsUnsafeOriginalFilename covers Q1: the sender chooses
// original_filename, so any value that is not a safe base name fails to parse.
func TestDecodeRejectsUnsafeOriginalFilename(t *testing.T) {
	fe := NewFileEncoder()
	for _, name := range []string{"../x", "../../victim/target.txt", "/abs/path", `a\b`, "c:x", "..", ".", "a\x00b", "a\nb", strings.Repeat("n", 256)} {
		h := validV2Password()
		h["original_filename"] = name
		if _, err := fe.Decode(buildV2Container(t, 0x03, 3, h)); err == nil {
			t.Errorf("original_filename %q decoded; want a parse error", name)
		}
	}
	for _, name := range []string{"", "report.pdf", "..hidden"} {
		h := validV2Password()
		h["original_filename"] = name
		if _, err := fe.Decode(buildV2Container(t, 0x03, 3, h)); err != nil {
			t.Errorf("original_filename %q: %v, want success", name, err)
		}
	}
}

// TestEncodeRejectsUnsafeOriginalFilename: the encoder never writes a header
// that a decoder would reject.
func TestEncodeRejectsUnsafeOriginalFilename(t *testing.T) {
	file := &entities.EncryptedFile{
		Version: entities.FormatVersion, Method: entities.MethodPassphrase,
		Salt: make([]byte, 16), KDF: entities.KDFArgon2id, KDFParams: entities.FileKDFParams,
		OriginalFilename: "../x", EncryptedAt: time.Unix(1700000000, 0),
	}
	if _, err := NewFileEncoder().EncodeHeader(file); err == nil {
		t.Fatal("EncodeHeader wrote original_filename \"../x\"")
	}
}

// TestHeaderJSONRules covers Q5: rules that make Go and the spec Python agree
// on every header. Each case would be accepted by a plain JSON parser in at
// least one language.
func TestHeaderJSONRules(t *testing.T) {
	fe := NewFileEncoder()
	deep := strings.Repeat("[", 9) + strings.Repeat("]", 9)
	cases := map[string]string{
		"NaN":                  passwordHeaderWith(t, "x", "NaN"),
		"Infinity":             passwordHeaderWith(t, "x", "Infinity"),
		"fraction":             passwordHeaderWith(t, "encrypted_at", "1700000000.5"),
		"integral fraction":    passwordHeaderWith(t, "encrypted_at", "1700000000.0"),
		"exponent":             passwordHeaderWith(t, "encrypted_at", "17e8"),
		"negative":             passwordHeaderWith(t, "encrypted_at", "-1"),
		"negative zero":        passwordHeaderWith(t, "encrypted_at", "-0"),
		"above 2^53-1":         passwordHeaderWith(t, "encrypted_at", "9007199254740992"),
		"400-digit integer":    passwordHeaderWith(t, "x", strings.Repeat("9", 400)),
		"lone surrogate":       passwordHeaderWith(t, "x", `"\ud800"`),
		"nesting 9 levels":     passwordHeaderWith(t, "x", deep),
		"unknown member float": passwordHeaderWith(t, "x", "0.1"),
	}
	for name, header := range cases {
		if _, err := fe.Decode(rawContainer(header)); err == nil {
			t.Errorf("%s: header decoded; want a parse error", name)
		}
	}
	okCases := map[string]string{
		"2^53-1":           passwordHeaderWith(t, "encrypted_at", "9007199254740991"),
		"nesting 8 levels": passwordHeaderWith(t, "x", strings.Repeat("[", 7)+strings.Repeat("]", 7)),
		"unknown string":   passwordHeaderWith(t, "x", `"future"`),
	}
	for name, header := range okCases {
		if _, err := fe.Decode(rawContainer(header)); err != nil {
			t.Errorf("%s: %v, want success", name, err)
		}
	}
}
