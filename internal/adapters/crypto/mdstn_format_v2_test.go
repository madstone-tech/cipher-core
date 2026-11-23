package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// buildV2Container returns magic | version | method | u16be(len) | headerJSON.
func buildV2Container(t *testing.T, version, method byte, header map[string]any) []byte {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(mdstMagic), version, method)
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerJSON))) // #nosec G115 -- small test header
	return append(out, headerJSON...)
}

func b64(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, n)) }

// validV2Recipients returns a well-formed method-2 header map with n blocks.
func validV2Recipients(n int) map[string]any {
	blocks := make([]any, 0, n)
	for range n {
		blocks = append(blocks, map[string]any{
			"ephemeral_pub_key": b64(32),
			"nonce":             b64(12),
			"wrapped_cek":       b64(48),
		})
	}
	return map[string]any{
		"chunked":           false,
		"original_filename": "a.txt",
		"encrypted_at":      1700000000,
		"recipients":        blocks,
	}
}

// validV2Password returns a well-formed method-3 header map.
func validV2Password() map[string]any {
	return map[string]any{
		"chunked":           true,
		"original_filename": "a.txt",
		"encrypted_at":      1700000000,
		"kdf":               "argon2id",
		"salt":              b64(16),
		"m":                 65536,
		"t":                 3,
		"p":                 4,
	}
}

func TestDecodeV2Header(t *testing.T) {
	fe := NewFileEncoder()

	t.Run("controls decode", func(t *testing.T) {
		file, err := fe.Decode(buildV2Container(t, 3, 2, validV2Recipients(2)))
		if err != nil {
			t.Fatalf("method 2: %v", err)
		}
		if file.Version != 3 || len(file.Recipients) != 2 {
			t.Errorf("method 2 decoded as %+v", file)
		}
		file, err = fe.Decode(buildV2Container(t, 3, 3, validV2Password()))
		if err != nil {
			t.Fatalf("method 3: %v", err)
		}
		if file.KDF != entities.KDFArgon2id || file.KDFParams != entities.FileKDFParams || len(file.Salt) != 16 {
			t.Errorf("method 3 decoded as %+v", file)
		}
	})

	forbidden := map[string]any{
		"key_id":            "abcd",
		"recipient_key_id":  "abcd",
		"fingerprint_hint":  b64(8),
		"ephemeral_pub_key": b64(32),
		"nonce":             b64(12),
		"encrypted_data":    b64(60),
	}
	for field, value := range forbidden {
		for _, empty := range []bool{false, true} {
			v := value
			if empty {
				v = ""
			}
			t.Run("method 2 top-level "+field, func(t *testing.T) {
				h := validV2Recipients(1)
				h[field] = v
				if _, err := fe.Decode(buildV2Container(t, 3, 2, h)); err == nil {
					t.Fatalf("v2 header with %s=%q parsed", field, v)
				}
			})
			t.Run("method 3 top-level "+field, func(t *testing.T) {
				h := validV2Password()
				h[field] = v
				if _, err := fe.Decode(buildV2Container(t, 3, 3, h)); err == nil {
					t.Fatalf("v2 header with %s=%q parsed", field, v)
				}
			})
		}
	}

	t.Run("fingerprint_hint in a block", func(t *testing.T) {
		for _, v := range []string{b64(8), ""} {
			h := validV2Recipients(2)
			h["recipients"].([]any)[1].(map[string]any)["fingerprint_hint"] = v
			if _, err := fe.Decode(buildV2Container(t, 3, 2, h)); err == nil {
				t.Fatalf("v2 block with fingerprint_hint=%q parsed", v)
			}
		}
	})

	t.Run("block count", func(t *testing.T) {
		for _, n := range []int{0, 17} {
			if _, err := fe.Decode(buildV2Container(t, 3, 2, validV2Recipients(n))); err == nil {
				t.Errorf("v2 header with %d blocks parsed", n)
			}
		}
		h := validV2Recipients(1)
		delete(h, "recipients")
		if _, err := fe.Decode(buildV2Container(t, 3, 2, h)); err == nil {
			t.Error("v2 header without recipients parsed")
		}
		if _, err := fe.Decode(buildV2Container(t, 3, 2, validV2Recipients(16))); err != nil {
			t.Errorf("16 blocks: %v", err)
		}
	})

	t.Run("block field sizes", func(t *testing.T) {
		for field, size := range map[string]int{"ephemeral_pub_key": 31, "nonce": 11, "wrapped_cek": 47} {
			h := validV2Recipients(1)
			h["recipients"].([]any)[0].(map[string]any)[field] = b64(size)
			if _, err := fe.Decode(buildV2Container(t, 3, 2, h)); err == nil {
				t.Errorf("block with %d-byte %s parsed", size, field)
			}
		}
	})

	t.Run("method 3 parameters are fixed", func(t *testing.T) {
		mutations := map[string]func(map[string]any){
			"m=65535":       func(h map[string]any) { h["m"] = 65535 },
			"m=131072":      func(h map[string]any) { h["m"] = 131072 },
			"t=2":           func(h map[string]any) { h["t"] = 2 },
			"t=4":           func(h map[string]any) { h["t"] = 4 },
			"p=1":           func(h map[string]any) { h["p"] = 1 },
			"p=8":           func(h map[string]any) { h["p"] = 8 },
			"m as string":   func(h map[string]any) { h["m"] = "65536" },
			"t=3.5":         func(h map[string]any) { h["t"] = 3.5 },
			"m missing":     func(h map[string]any) { delete(h, "m") },
			"t missing":     func(h map[string]any) { delete(h, "t") },
			"p missing":     func(h map[string]any) { delete(h, "p") },
			"kdf=pbkdf2":    func(h map[string]any) { h["kdf"] = "pbkdf2-sha256-600k" },
			"kdf missing":   func(h map[string]any) { delete(h, "kdf") },
			"salt 32 bytes": func(h map[string]any) { h["salt"] = b64(32) },
			"salt missing":  func(h map[string]any) { delete(h, "salt") },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				h := validV2Password()
				mutate(h)
				if _, err := fe.Decode(buildV2Container(t, 3, 3, h)); err == nil {
					t.Fatal("parsed; want a parse error before any KDF runs")
				}
			})
		}
	})

	t.Run("chunked is required", func(t *testing.T) {
		h := validV2Password()
		delete(h, "chunked")
		if _, err := fe.Decode(buildV2Container(t, 3, 3, h)); err == nil {
			t.Fatal("v2 header without chunked parsed")
		}
	})

	t.Run("unsupported versions", func(t *testing.T) {
		for _, v := range []byte{0x00, 0x02, 0x04, 0xFF} {
			_, err := fe.Decode(buildV2Container(t, v, 3, validV2Password()))
			if err == nil || !strings.Contains(err.Error(), "unsupported version") {
				t.Errorf("version 0x%02x: err = %v, want \"unsupported version\"", v, err)
			}
			_, _, err = fe.DecodeHeader(bytes.NewReader(buildV2Container(t, v, 3, validV2Password())))
			if err == nil || !strings.Contains(err.Error(), "unsupported version") {
				t.Errorf("DecodeHeader version 0x%02x: err = %v, want \"unsupported version\"", v, err)
			}
		}
	})
}

func TestEncodeV2Header(t *testing.T) {
	fe := NewFileEncoder()
	salt := bytes.Repeat([]byte{1}, 16)
	file := &entities.EncryptedFile{
		Version:          entities.FormatVersion,
		Method:           entities.MethodPassphrase,
		Chunked:          true,
		Salt:             salt,
		KDF:              entities.KDFArgon2id,
		KDFParams:        entities.FileKDFParams,
		OriginalFilename: "x.bin",
		EncryptedAt:      time.Unix(1700000000, 0),
	}
	header, err := fe.EncodeHeader(file)
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	if header[4] != 0x03 || header[5] != 3 {
		t.Fatalf("version/method bytes = %#x/%#x, want 0x03/3", header[4], header[5])
	}
	var fields map[string]any
	if err := json.Unmarshal(header[8:], &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"key_id", "recipient_key_id", "ephemeral_pub_key", "nonce", "encrypted_data", "fingerprint_hint", "recipients"} {
		if _, ok := fields[key]; ok {
			t.Errorf("v2 method-3 header has %q", key)
		}
	}

	got, aad, err := fe.DecodeHeader(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if !bytes.Equal(aad, header) || got.KDFParams != entities.FileKDFParams || !bytes.Equal(got.Salt, salt) {
		t.Errorf("round trip: %+v", got)
	}

	t.Run("method 2 has no v1 fields", func(t *testing.T) {
		f := &entities.EncryptedFile{
			Version: entities.FormatVersion,
			Method:  entities.MethodX25519,
			Recipients: []entities.RecipientBlock{{
				EphemeralPubKey: b64(32), Nonce: b64(12), WrappedCEK: b64(48),
			}},
			EncryptedAt: time.Unix(1700000000, 0),
		}
		h, err := fe.EncodeHeader(f)
		if err != nil {
			t.Fatalf("EncodeHeader: %v", err)
		}
		if strings.Contains(string(h), "fingerprint_hint") || strings.Contains(string(h), "key_id") {
			t.Errorf("v2 method-2 header has v1 fields: %s", h[8:])
		}
	})

	t.Run("production encoder does not write v1", func(t *testing.T) {
		v1 := *file
		v1.Version = 1
		v1.KDF, v1.KDFParams = "", entities.KDFParams{}
		if _, err := fe.EncodeHeader(&v1); err == nil {
			t.Error("EncodeHeader wrote a version 0x01 header")
		}
	})
}

func TestDecodeHeaderLeavesReaderAtBody(t *testing.T) {
	fe := NewFileEncoder()
	header := buildV2Container(t, 3, 3, validV2Password())
	body := []byte("body-bytes-follow")
	r := bytes.NewReader(append(append([]byte{}, header...), body...))

	_, aad, err := fe.DecodeHeader(r)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if !bytes.Equal(aad, header) {
		t.Error("headerAAD differs from the header bytes")
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, body) {
		t.Errorf("reader left at %q, want the body", rest)
	}

	for _, n := range []int{0, 3, 7, 8, len(header) - 1} {
		if _, _, err := fe.DecodeHeader(bytes.NewReader(header[:n])); err == nil {
			t.Errorf("DecodeHeader accepted a %d-byte truncated header", n)
		}
	}
}

// TestHeaderMAC checks the key schedule against docs/format-spec.md (computed
// here with the standard library), that the MAC binds every header byte, and
// that VerifyHeaderMAC rejects a wrong key and malformed input.
func TestHeaderMAC(t *testing.T) {
	engine := NewEngine()
	fileKey := randomKey(t)
	header := buildV2Container(t, 3, 3, validV2Password())
	wantMAC, wantPayload := specFileKeys(t, fileKey, header)

	mac, err := engine.HeaderMAC(fileKey, header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mac, wantMAC) || len(mac) != entities.HeaderMACSize {
		t.Fatal("HeaderMAC differs from HMAC-SHA256(HKDF(file_key, \"mdstn-cipher/v2/header-mac\"), headerAAD)")
	}
	payload, err := engine.DerivePayloadKey(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, wantPayload) || bytes.Equal(payload, fileKey) {
		t.Fatal("DerivePayloadKey differs from HKDF(file_key, \"mdstn-cipher/v2/payload\")")
	}

	if ok, err := engine.VerifyHeaderMAC(fileKey, header, mac); err != nil || !ok {
		t.Fatalf("VerifyHeaderMAC(control) = %v, %v", ok, err)
	}
	for i := range header {
		flipped := append([]byte{}, header...)
		flipped[i] ^= 0x01
		if ok, err := engine.VerifyHeaderMAC(fileKey, flipped, mac); err != nil || ok {
			t.Fatalf("header byte %d flipped: VerifyHeaderMAC = %v, %v; want false", i, ok, err)
		}
	}
	if ok, err := engine.VerifyHeaderMAC(randomKey(t), header, mac); err != nil || ok {
		t.Fatalf("wrong key: VerifyHeaderMAC = %v, %v; want false", ok, err)
	}
	if _, err := engine.VerifyHeaderMAC(fileKey, header, mac[:31]); err == nil {
		t.Error("31-byte MAC accepted")
	}
	if _, err := engine.HeaderMAC(fileKey[:16], header); err == nil {
		t.Error("16-byte file key accepted")
	}
}

// TestDeriveFileKeyArgon2id pins the v2 method-3 KDF to the header parameters.
func TestDeriveFileKeyArgon2id(t *testing.T) {
	if got := (entities.KDFParams{M: argon2Memory, T: argon2Time, P: argon2Threads}); got != entities.FileKDFParams {
		t.Fatalf("engine parameters %+v differ from the v2 header parameters %+v", got, entities.FileKDFParams)
	}
	salt := bytes.Repeat([]byte{3}, 16)
	key, err := NewEngine().DeriveFileKeyArgon2id("pw", salt)
	if err != nil {
		t.Fatal(err)
	}
	want := argon2.IDKey([]byte("pw"), salt, 3, 65536, 4, 32)
	if !bytes.Equal(key, want) {
		t.Fatal("DeriveFileKeyArgon2id differs from Argon2id(m=65536, t=3, p=4, 32)")
	}
	if _, err := NewEngine().DeriveFileKeyArgon2id("pw", make([]byte, 32)); err == nil {
		t.Error("32-byte salt accepted")
	}
	if _, err := NewEngine().DeriveFileKeyArgon2id("", salt); err == nil {
		t.Error("empty password accepted")
	}
}
