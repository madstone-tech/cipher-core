package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// formatV2 is the container version byte.
const formatV2 = entities.FormatVersion

// streamChunkNonce derives the nonce of chunk counter: the base nonce with the
// big-endian uint64 counter XOR-ed into its last 8 bytes.
func streamChunkNonce(baseNonce []byte, counter uint64) []byte {
	nonce := append([]byte{}, baseNonce...)
	for i, b := range binary.BigEndian.AppendUint64(nil, counter) {
		nonce[4+i] ^= b
	}
	return nonce
}

// sealStreamV2 encrypts plain with EncryptStream and splits the v2 body into
// the base nonce and the frames (each u32be(len) || ct). It checks that the
// body ends with exactly one u32(0) terminator.
func sealStreamV2(t *testing.T, key, aad, plain []byte) (baseNonce []byte, frames [][]byte) {
	t.Helper()
	var out bytes.Buffer
	if err := NewEngine().EncryptStream(context.Background(), bytes.NewReader(plain), &out, key, aad); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	b := out.Bytes()
	baseNonce, b = b[:aesGCMNonceSize], b[aesGCMNonceSize:]
	for {
		n := binary.BigEndian.Uint32(b[:4])
		if n == 0 {
			if len(b) != 4 {
				t.Fatalf("%d bytes after the terminator", len(b)-4)
			}
			return baseNonce, frames
		}
		size := 4 + int(n)
		frames = append(frames, b[:size])
		b = b[size:]
	}
}

// joinV2 joins the base nonce and frames, and appends the terminator if term.
func joinV2(baseNonce []byte, term bool, frames ...[]byte) []byte {
	out := append([]byte{}, baseNonce...)
	for _, f := range frames {
		out = append(out, f...)
	}
	if term {
		out = append(out, 0, 0, 0, 0)
	}
	return out
}

// sealFrameV2 seals pt as frame index of a v2 stream with the given final flag,
// for streams that EncryptStream cannot produce.
func sealFrameV2(t *testing.T, key, baseNonce, aad []byte, index uint64, final bool, pt []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	frameAAD := binary.BigEndian.AppendUint64(append([]byte{}, aad...), index)
	if final {
		frameAAD = append(frameAAD, 1)
	} else {
		frameAAD = append(frameAAD, 0)
	}
	ct := gcm.Seal(nil, streamChunkNonce(baseNonce, index), pt, frameAAD)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(ct))), ct...) // #nosec G115 -- test frame ≤ 65552 bytes
}

// decryptV2 runs DecryptStream.
func decryptV2(key, aad, stream []byte) ([]byte, error) {
	var out bytes.Buffer
	err := NewEngine().DecryptStream(context.Background(), bytes.NewReader(stream), &out, key, aad)
	return out.Bytes(), err
}

// requireChunkAuthError checks that err is a tamper-class *ChunkAuthError and
// returns it.
func requireChunkAuthError(t *testing.T, err error) *entities.ChunkAuthError {
	t.Helper()
	if err == nil {
		t.Fatal("manipulated stream decrypted; want error")
	}
	if !errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Errorf("errors.Is(err, ErrHeaderAuthFailed) = false; err = %v", err)
	}
	var chunkErr *entities.ChunkAuthError
	if !errors.As(err, &chunkErr) {
		t.Fatalf("errors.As(err, *ChunkAuthError) = false; err = %v", err)
	}
	return chunkErr
}

func TestStreamV2Truncation(t *testing.T) {
	key := randomKey(t)
	aad := []byte("header-aad")
	sizes := []int{0, 1, 65535, 65536, 65537, 3 * 65536, 3*65536 + 5}

	for _, size := range sizes {
		plain := bytes.Repeat([]byte{0x5A}, size)
		for i := range plain {
			plain[i] = byte(i * 7)
		}
		base, frames := sealStreamV2(t, key, aad, plain)
		wantFrames := max(1, (size+streamChunkSize-1)/streamChunkSize)
		if len(frames) != wantFrames {
			t.Fatalf("size %d: %d frames, want %d", size, len(frames), wantFrames)
		}

		t.Run(fmt.Sprintf("size=%d/unchanged", size), func(t *testing.T) {
			got, err := decryptV2(key, aad, joinV2(base, true, frames...))
			if err != nil {
				t.Fatalf("DecryptStream(unchanged): %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("round trip differs")
			}
		})

		// Keep the first k frames, k < n, with and without a terminator.
		for k := range len(frames) {
			for _, term := range []bool{true, false} {
				t.Run(fmt.Sprintf("size=%d/keep=%d/terminator=%t", size, k, term), func(t *testing.T) {
					_, err := decryptV2(key, aad, joinV2(base, term, frames[:k]...))
					requireChunkAuthError(t, err)
				})
			}
		}

		t.Run(fmt.Sprintf("size=%d/all-frames-no-terminator", size), func(t *testing.T) {
			_, err := decryptV2(key, aad, joinV2(base, false, frames...))
			requireChunkAuthError(t, err)
		})

		for _, extra := range [][]byte{{0x00}, {0xAA, 0xBB}, {0, 0, 0, 0}} {
			t.Run(fmt.Sprintf("size=%d/trailing=%x", size, extra), func(t *testing.T) {
				_, err := decryptV2(key, aad, append(joinV2(base, true, frames...), extra...))
				requireChunkAuthError(t, err)
			})
		}
	}
}

func TestStreamV2Frames(t *testing.T) {
	key := randomKey(t)
	aad := []byte("header-aad")
	plain := make([]byte, 3*streamChunkSize+5)
	for i := range plain {
		plain[i] = byte(i / streamChunkSize)
	}
	base, f := sealStreamV2(t, key, aad, plain)
	if len(f) != 4 {
		t.Fatalf("%d frames, want 4", len(f))
	}

	forged := binary.BigEndian.AppendUint32(nil, streamChunkSize+16+1)
	forged = append(forged, f[1][4:]...)
	forged = append(forged, 0x00)

	shortMid := sealFrameV2(t, key, base, aad, 1, false, plain[streamChunkSize:2*streamChunkSize-1])
	lastAsMid := sealFrameV2(t, key, base, aad, 3, false, plain[3*streamChunkSize:])

	cases := []struct {
		name   string
		stream []byte
		index  uint64 // the chunk index that the ChunkAuthError carries
	}{
		{"swap frames 0 and 1", joinV2(base, true, f[1], f[0], f[2], f[3]), 0},
		{"swap frames 1 and 2", joinV2(base, true, f[0], f[2], f[1], f[3]), 1},
		{"swap first and last", joinV2(base, true, f[3], f[1], f[2], f[0]), 0},
		{"repeat frame 0", joinV2(base, true, f[0], f[0], f[0], f[3]), 1},
		{"repeat frame 2 everywhere", joinV2(base, true, f[2], f[2], f[2], f[2]), 0},
		{"remove frame 0", joinV2(base, true, f[1], f[2], f[3]), 0},
		{"remove middle frame", joinV2(base, true, f[0], f[2], f[3]), 1},
		{"forged length 65553", joinV2(base, true, f[0], forged, f[2], f[3]), 1},
		{"non-final frame with 65535-byte plaintext", joinV2(base, true, f[0], shortMid, f[2], f[3]), 1},
		{"last frame sealed as non-final", joinV2(base, true, f[0], f[1], f[2], lastAsMid), 3},
		{"len 0 as the first frame", joinV2(base, true), 0},
		{"len 0 as the first frame, then frames", append(joinV2(base, true), joinV2(nil, true, f...)...), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decryptV2(key, aad, tc.stream)
			if chunkErr := requireChunkAuthError(t, err); chunkErr.Index != tc.index {
				t.Errorf("ChunkAuthError.Index = %d, want %d; err = %v", chunkErr.Index, tc.index, err)
			}
		})
	}

	t.Run("bit flip in frame 0", func(t *testing.T) {
		flipped := append([]byte{}, f[0]...)
		flipped[len(flipped)-1] ^= 0x01
		_, err := decryptV2(key, aad, joinV2(base, true, flipped, f[1], f[2], f[3]))
		if chunkErr := requireChunkAuthError(t, err); chunkErr.Index != 0 {
			t.Errorf("want ChunkAuthError{Index: 0}; got %+v", chunkErr)
		}
	})

	t.Run("wrong key fails at chunk 0 after reading frame 0 only", func(t *testing.T) {
		stream := joinV2(base, true, f...)
		src := &countingReader{r: bytes.NewReader(stream)}
		err := NewEngine().DecryptStream(context.Background(), src, &bytes.Buffer{}, randomKey(t), aad)
		if chunkErr := requireChunkAuthError(t, err); chunkErr.Index != 0 {
			t.Errorf("want ChunkAuthError{Index: 0}; got %+v", chunkErr)
		}
		if want := len(base) + len(f[0]) + 4; src.n > want {
			t.Errorf("read %d bytes, want ≤ %d (base nonce, frame 0, next length)", src.n, want)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		got, err := decryptV2(key, aad, joinV2(base, true, f...))
		if err != nil {
			t.Fatalf("DecryptStream(unchanged): %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("round trip differs")
		}
	})
}
