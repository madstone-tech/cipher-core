package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// BenchmarkStream measures stream throughput on a 100 MiB input.
func BenchmarkStream(b *testing.B) {
	const size = 100 << 20
	plain := bytes.Repeat([]byte{0x5a}, size)
	key := bytes.Repeat([]byte{1}, 32)
	aad := []byte("bench-header")
	e := NewEngine()
	ctx := context.Background()

	var sealed bytes.Buffer
	sealed.Grow(size + size/64)
	b.Run("encrypt", func(b *testing.B) {
		b.SetBytes(size)
		for b.Loop() {
			sealed.Reset()
			if err := e.EncryptStream(ctx, bytes.NewReader(plain), &sealed, key, aad); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("decrypt", func(b *testing.B) {
		b.SetBytes(size)
		for b.Loop() {
			if err := e.DecryptStream(ctx, bytes.NewReader(sealed.Bytes()), io.Discard, key, aad); err != nil {
				b.Fatal(err)
			}
		}
	})
}
