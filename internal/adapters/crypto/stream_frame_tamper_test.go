package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// countingReader counts the bytes handed out by the underlying reader.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestDecryptStreamBoundsChunkLength feeds a 28-byte input whose length field
// claims ~4 GiB. DecryptStream must fail with the tamper class without
// allocating the claimed size and without reading past the input.
func TestDecryptStreamBoundsChunkLength(t *testing.T) {
	key := randomKey(t)

	input := make([]byte, 0, 28)
	input = append(input, make([]byte, aesGCMNonceSize)...) // base nonce
	input = binary.BigEndian.AppendUint32(input, 0xFFFFFFF0)
	input = append(input, make([]byte, aesGCMNonceSize)...) // ciphertext
	if len(input) != 28 {
		t.Fatalf("input length = %d, want 28", len(input))
	}

	src := &countingReader{r: bytes.NewReader(input)}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := NewEngine().DecryptStream(context.Background(), src, io.Discard, key, []byte("header"))
	runtime.ReadMemStats(&after)

	requireChunkAuthError(t, err)
	if src.n > 28 {
		t.Errorf("read %d bytes, want ≤ 28", src.n)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown >= 1<<20 {
		t.Errorf("TotalAlloc grew by %d bytes, want < 1 MiB", grown)
	}
}
