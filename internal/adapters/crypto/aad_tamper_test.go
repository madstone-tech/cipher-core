package crypto

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// The tamper matrix of the single container format (docs/format-spec.md
// §Error classes). Each row changes a committed vector and decrypts it with
// referenceDecrypt and the vector's own key material; no row may decrypt, and
// each fails with its class.

// vectorByName returns the vector name of vectors.json and its fixture bytes.
func vectorByName(t *testing.T, name string) (conformanceVector, []byte) {
	t.Helper()
	for _, v := range loadConformanceVectors(t).Vectors {
		if v.Name == name {
			return v, readFixture(t, v)
		}
	}
	t.Fatalf("vectors.json has no vector %q", name)
	return conformanceVector{}, nil
}

// classOf decrypts data with v's key material and returns the failure class,
// or "ok" when it decrypts.
func classOf(engine *Engine, v conformanceVector, data []byte) string {
	if _, _, err := referenceDecrypt(engine, v, data); err != nil {
		return errorClass(err)
	}
	return "ok"
}

func flipped(data []byte, i int) []byte {
	out := append([]byte{}, data...)
	out[i] ^= 0x01
	return out
}

func headerEnd(data []byte) int {
	return 8 + int(binary.BigEndian.Uint16(data[6:8]))
}

// TestTamperHeaderByteSweep flips every header byte of a method-5 and a
// method-2 file. The header is the MAC input, so a change that still parses
// fails the MAC (method 5: tamper) or changes the recipient block (method 2:
// no block opens, or a block opens and the MAC fails: tamper).
func TestTamperHeaderByteSweep(t *testing.T) {
	engine := NewEngine()
	for _, tc := range []struct {
		vector  string
		allowed []string
	}{
		{"sharedkey", []string{expectParse, expectTamper}},
		{"x25519-single", []string{expectParse, expectTamper, expectNotARecipient}},
	} {
		v, data := vectorByName(t, tc.vector)
		for i := range headerEnd(data) {
			got := classOf(engine, v, flipped(data, i))
			if !slices.Contains(tc.allowed, got) {
				t.Errorf("%s: header byte %d flipped: class %s, want one of %v", tc.vector, i, got, tc.allowed)
			}
		}
	}
}

// TestTamperHeaderMAC flips each header MAC byte: method 3 reports a wrong
// password (the MAC is the key check), methods 2 and 5 report tampering.
func TestTamperHeaderMAC(t *testing.T) {
	engine := NewEngine()
	for _, tc := range []struct {
		vector string
		want   string
		bytes  []int
	}{
		{"sharedkey", expectTamper, nil},
		{"x25519-single", expectTamper, nil},
		{"passphrase", expectWrongPassword, []int{0, 31}}, // Argon2id per row: two rows
	} {
		v, data := vectorByName(t, tc.vector)
		start := headerEnd(data)
		rows := tc.bytes
		if rows == nil {
			for i := range entities.HeaderMACSize {
				rows = append(rows, i)
			}
		}
		for _, i := range rows {
			if got := classOf(engine, v, flipped(data, start+i)); got != tc.want {
				t.Errorf("%s: MAC byte %d flipped: class %s, want %s", tc.vector, i, got, tc.want)
			}
		}
		// A body that ends inside the MAC is a parse error.
		if got := classOf(engine, v, data[:start+entities.HeaderMACSize-1]); got != expectParse {
			t.Errorf("%s: MAC truncated: class %s, want %s", tc.vector, got, expectParse)
		}
	}
}

// TestTamperVersionByte: every version byte except 0x03 fails to parse with
// "unsupported version", before the header JSON or any key is used.
func TestTamperVersionByte(t *testing.T) {
	_, data := vectorByName(t, "sharedkey")
	for _, version := range []byte{0x00, 0x01, 0x02, 0x04, 0xff} {
		bad := append([]byte{}, data...)
		bad[4] = version
		_, _, _, err := NewFileEncoder().DecodeWithOffset(bad)
		if err == nil || !strings.Contains(err.Error(), "unsupported version") {
			t.Errorf("version 0x%02x: err %v, want unsupported version", version, err)
		}
	}
}

// TestTamperBodyRows changes the body after a valid MAC: every row is
// tampering, in both framings.
func TestTamperBodyRows(t *testing.T) {
	engine := NewEngine()

	v, single := vectorByName(t, "sharedkey")
	body := headerEnd(single) + entities.HeaderMACSize
	singleRows := map[string][]byte{
		"nonce byte flipped":     flipped(single, body),
		"ciphertext flipped":     flipped(single, body+12),
		"tag flipped":            flipped(single, len(single)-1),
		"body shorter than 28":   single[:body+27],
		"body empty":             single[:body],
		"trailing byte appended": append(append([]byte{}, single...), 0),
	}
	for name, data := range singleRows {
		if got := classOf(engine, v, data); got != expectTamper {
			t.Errorf("single frame, %s: class %s, want %s", name, got, expectTamper)
		}
	}

	v, stream := vectorByName(t, "sharedkey-chunked")
	head, frames := splitStreamContainer(t, stream)
	if len(frames) != 4 {
		t.Fatalf("sharedkey-chunked has %d frames, want 4", len(frames))
	}
	nonceAt := len(head) - aesGCMNonceSize
	frame0 := len(head)
	swapped := joinStreamContainer(head, true, frames[1], frames[0], frames[2], frames[3])
	streamRows := map[string][]byte{
		"base nonce flipped":         flipped(stream, nonceAt),
		"frame 0 length flipped":     flipped(stream, frame0+3),
		"frame 0 ciphertext flipped": flipped(stream, frame0+4),
		"final frame tag flipped":    flipped(stream, len(stream)-5),
		"frames 0 and 1 swapped":     swapped,
		"terminator removed":         stream[:len(stream)-4],
		"terminator only":            joinStreamContainer(head, true),
		"truncated at boundary":      joinStreamContainer(head, true, frames[:3]...),
		"frame 0 removed":            joinStreamContainer(head, true, frames[1:]...),
		"frame after final":          joinStreamContainer(head, true, append(append([][]byte{}, frames...), frames[1])...),
		"trailing byte appended":     append(append([]byte{}, stream...), 0),
		"no base nonce":              stream[:len(head)-1],
	}
	for name, data := range streamRows {
		if got := classOf(engine, v, data); got != expectTamper {
			t.Errorf("stream, %s: class %s, want %s", name, got, expectTamper)
		}
	}
}
