package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// buildMdstnWithRawHeader assembles a .mdstn header around a caller-supplied
// header JSON. The JSON is written verbatim rather than being produced by
// json.Marshal, so tests can express headers that a conforming encoder cannot
// emit (duplicate members, invalid UTF-8).
func buildMdstnWithRawHeader(method byte, headerJSON []byte) []byte {
	out := append([]byte(mdstMagic), entities.FormatVersion, method)
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerJSON))) // #nosec G115 -- small test header
	return append(out, headerJSON...)
}

// TestDecode_RejectsDuplicateHeaderMember verifies that a header carrying the
// same member twice is rejected outright rather than silently resolved
// last-wins. The header steers key selection before it is authenticated (the
// header MAC needs the file key), so a Go/JS disagreement over which value
// wins is a parser differential we refuse to inherit.
func TestDecode_RejectsDuplicateHeaderMember(t *testing.T) {
	raw := []byte(`{"chunked":false,"policy_id":"first","policy_id":"second"}`)
	if _, err := NewFileEncoder().Decode(buildMdstnWithRawHeader(5, raw)); err == nil {
		t.Fatal("Decode accepted a header with a duplicate policy_id; expected rejection")
	}
}

// TestDecode_RejectsInvalidUTF8InHeader verifies that a header string holding
// bytes that are not valid UTF-8 is rejected instead of being silently rewritten
// with replacement characters.
func TestDecode_RejectsInvalidUTF8InHeader(t *testing.T) {
	raw := []byte("{\"chunked\":false,\"policy_id\":\"p\",\"original_filename\":\"bad\xff\xfe.txt\"}")
	if _, err := NewFileEncoder().Decode(buildMdstnWithRawHeader(5, raw)); err == nil {
		t.Fatal("Decode accepted a header containing invalid UTF-8; expected rejection")
	}
}

// TestDecode_AcceptsWellFormedHeader guards the hardening against overreach: a
// header with an unknown member (forward compatibility) still decodes.
func TestDecode_AcceptsWellFormedHeader(t *testing.T) {
	raw := []byte(`{"chunked":false,"encrypted_at":1234567890,"future_field":"ignored","original_filename":"notes.txt","policy_id":"p"}`)
	decoded, err := NewFileEncoder().Decode(buildMdstnWithRawHeader(5, raw))
	if err != nil {
		t.Fatalf("Decode rejected a well-formed header: %v", err)
	}
	if decoded.OriginalFilename != "notes.txt" || decoded.PolicyID != "p" || decoded.Version != entities.FormatVersion {
		t.Errorf("decoded = %+v", decoded)
	}
}

// TestEncodeDecode_MultiRecipientHeaderSize verifies bounded header growth for
// multi-recipient files: < 256 bytes of header per recipient block and < 4 KB
// for 16 blocks, and the blocks round-trip.
func TestEncodeDecode_MultiRecipientHeaderSize(t *testing.T) {
	fe := NewFileEncoder()
	buildFile := func(n int) *entities.EncryptedFile {
		recipients := make([]entities.RecipientBlock, n)
		for i := range recipients {
			recipients[i] = entities.RecipientBlock{
				EphemeralPubKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i)}, 32)),
				Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 12)),
				WrappedCEK:      base64.StdEncoding.EncodeToString(make([]byte, 48)),
			}
		}
		return &entities.EncryptedFile{
			Version: entities.FormatVersion, Method: entities.MethodX25519, Recipients: recipients,
			OriginalFilename: "size.txt", EncryptedAt: time.Now(),
		}
	}
	headerLen := func(t *testing.T, file *entities.EncryptedFile) int {
		t.Helper()
		encoded, err := fe.EncodeHeader(file)
		if err != nil {
			t.Fatalf("EncodeHeader: %v", err)
		}
		decoded, err := fe.Decode(encoded)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if len(decoded.Recipients) != len(file.Recipients) {
			t.Fatalf("recipients round-trip: got %d, want %d", len(decoded.Recipients), len(file.Recipients))
		}
		for i := range file.Recipients {
			if decoded.Recipients[i] != file.Recipients[i] {
				t.Fatalf("block %d differs after the round trip", i)
			}
		}
		return int(binary.BigEndian.Uint16(encoded[6:8]))
	}

	n1 := headerLen(t, buildFile(1))
	n16 := headerLen(t, buildFile(16))
	if perRecipient := (n16 - n1) / 15; perRecipient >= 256 {
		t.Errorf("header overhead per recipient = %d bytes, want < 256", perRecipient)
	}
	if n16 >= 4096 {
		t.Errorf("header for 16 recipients = %d bytes, want < 4096", n16)
	}
}

// BenchmarkEncrypt16Recipients measures the wrap and header encoding of a
// 16-recipient file.
func BenchmarkEncrypt16Recipients(b *testing.B) {
	engine := NewEngine()
	fe := NewFileEncoder()
	pubs := make([][]byte, 16)
	for i := range pubs {
		pub, _, err := engine.GenerateX25519Keypair()
		if err != nil {
			b.Fatal(err)
		}
		pubs[i] = pub
	}

	for b.Loop() {
		cek, err := engine.GenerateAESKey()
		if err != nil {
			b.Fatalf("GenerateAESKey: %v", err)
		}
		recipients := make([]entities.RecipientBlock, 0, 16)
		for _, pub := range pubs {
			ephPub, wrapNonce, wrappedCEK, err := engine.WrapCEK(cek, pub, []byte(entities.WrapCEKAAD))
			if err != nil {
				b.Fatalf("WrapCEK: %v", err)
			}
			recipients = append(recipients, entities.RecipientBlock{
				EphemeralPubKey: base64.StdEncoding.EncodeToString(ephPub),
				Nonce:           base64.StdEncoding.EncodeToString(wrapNonce),
				WrappedCEK:      base64.StdEncoding.EncodeToString(wrappedCEK),
			})
		}
		if _, err := fe.EncodeHeader(&entities.EncryptedFile{
			Version: entities.FormatVersion, Method: entities.MethodX25519, Recipients: recipients,
			OriginalFilename: "bench.bin", EncryptedAt: time.Now(),
		}); err != nil {
			b.Fatalf("Encode: %v", err)
		}
		clear(cek)
	}
}
