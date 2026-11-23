package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

const (
	aesGCMNonceSize = 12
	streamChunkSize = 64 * 1024 // 64 KiB per spec §VIII
)

// chunkFailure wraps a structural stream violation at chunk index as an
// *entities.ChunkAuthError (tamper class).
func chunkFailure(index uint64, format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), &entities.ChunkAuthError{Index: index})
}

// isTruncation reports whether err means the input ended inside a frame.
func isTruncation(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// EncryptAES encrypts plaintext using AES-256-GCM.
// aad is the additional authenticated data (container header bytes for .mdstn
// operations; nil for AAD-free operations such as key generation).
func (e *Engine) EncryptAES(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce = make([]byte, aesGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// EncryptAESWithNonce encrypts plaintext using AES-256-GCM with a caller-supplied
// nonce. Container paths generate the body nonce in the usecase so the
// header (carrying the nonce) can be serialized and bound as AAD before the seal.
func (e *Engine) EncryptAESWithNonce(plaintext, key, nonce, aad []byte) (ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	if len(nonce) != aesGCMNonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d", aesGCMNonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	return aesgcm.Seal(nil, nonce, plaintext, aad), nil
}

// DecryptAES decrypts ciphertext using AES-256-GCM.
// aad must match the value passed to EncryptAES exactly.
func (e *Engine) DecryptAES(ciphertext, key, nonce, aad []byte) (plaintext []byte, err error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	// The nonce can come from a hostile header. gcm.Open panics on a wrong
	// nonce length, so reject it as an error.
	if len(nonce) != aesGCMNonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d", aesGCMNonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// newStreamGCM returns the AES-256-GCM AEAD for a stream key.
func newStreamGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}
	return gcm, nil
}

// stream holds the per-stream state that frame seals and opens share: the
// base nonce, and reusable nonce and AAD buffers.
type stream struct {
	gcm       cipher.AEAD
	baseNonce []byte
	nonce     []byte
	frameAAD  []byte // headerAAD || u64be(index) || u8(final)
	aadLen    int
}

func newStream(gcm cipher.AEAD, baseNonce, aad []byte) *stream {
	frameAAD := make([]byte, len(aad)+9)
	copy(frameAAD, aad)
	return &stream{
		gcm:       gcm,
		baseNonce: baseNonce,
		nonce:     make([]byte, aesGCMNonceSize),
		frameAAD:  frameAAD,
		aadLen:    len(aad),
	}
}

// set fills the nonce and the frame AAD for chunk index with the final flag:
// nonce = base_nonce XOR (0^4 || u64be(index)) (NIST SP 800-38D §8.2.1).
func (s *stream) set(index uint64, final bool) {
	copy(s.nonce, s.baseNonce)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], index)
	for i := range ctr {
		s.nonce[4+i] ^= ctr[i]
	}
	binary.BigEndian.PutUint64(s.frameAAD[s.aadLen:], index)
	s.frameAAD[s.aadLen+8] = 0
	if final {
		s.frameAAD[s.aadLen+8] = 1
	}
}

// open authenticates and decrypts ct as chunk index with the final flag,
// appending the plaintext to dst.
func (s *stream) open(dst, ct []byte, index uint64, final bool) ([]byte, error) {
	s.set(index, final)
	return s.gcm.Open(dst, s.nonce, ct, s.frameAAD)
}

// readChunk fills buf from src and returns the byte count. A short count
// means src is at its end; only other read errors are returned.
func readChunk(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, nil
	}
	if err != nil {
		return n, fmt.Errorf("failed to read source: %w", err)
	}
	return n, nil
}

// EncryptStream encrypts src into dst with the stream framing
// (docs/format-spec.md §Body; the STREAM construction):
//
//	base_nonce(12) || frame_0 .. frame_n || u32be(0)
//	frame_i = u32be(len_i) || ct_i
//	nonce_i = base_nonce XOR (0^4 || u64be(i))
//	ct_i    = AES-256-GCM(key, nonce_i, pt_i, aad || u64be(i) || u8(i == n))
//
// key is the payload key (DerivePayloadKey). The caller writes the header and
// the header MAC before it. Non-final chunks hold exactly 64 KiB of plaintext;
// the final chunk holds 1 to 64 KiB, or 0 bytes when it is the only chunk (an
// empty src). The encoder reads one chunk ahead to know which chunk is final,
// so a plaintext of k × 64 KiB ends with a full final chunk. aad is the
// container header bytes.
func (e *Engine) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte) error {
	gcm, err := newStreamGCM(key)
	if err != nil {
		return err
	}

	baseNonce := make([]byte, aesGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return fmt.Errorf("failed to generate base nonce: %w", err)
	}
	if _, err := dst.Write(baseNonce); err != nil {
		return fmt.Errorf("failed to write base nonce: %w", err)
	}
	s := newStream(gcm, baseNonce, aad)

	cur := make([]byte, streamChunkSize)
	next := make([]byte, streamChunkSize)
	frame := make([]byte, 0, 4+streamChunkSize+gcm.Overhead())

	n, err := readChunk(src, cur)
	if err != nil {
		return err
	}
	for counter := uint64(0); ; counter++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if counter == math.MaxUint64 {
			return fmt.Errorf("stream too large: chunk counter exhausted")
		}

		// A short chunk is the last one; a full chunk is the last one only if
		// nothing follows it.
		final := n < streamChunkSize
		m := 0
		if !final {
			if m, err = readChunk(src, next); err != nil {
				return err
			}
			final = m == 0
		}

		s.set(counter, final)
		frame = binary.BigEndian.AppendUint32(frame[:0], uint32(n+gcm.Overhead())) // #nosec G115 -- at most 64 KiB + 16; fits uint32
		frame = gcm.Seal(frame, s.nonce, cur[:n], s.frameAAD)
		if _, err := dst.Write(frame); err != nil {
			return fmt.Errorf("chunk %d: failed to write frame: %w", counter, err)
		}
		if final {
			break
		}
		cur, next, n = next, cur, m
	}

	if err := binary.Write(dst, binary.BigEndian, uint32(0)); err != nil {
		return fmt.Errorf("failed to write end-of-stream marker: %w", err)
	}
	return nil
}

// requireEOF checks that src ends right after the end-of-stream marker.
func requireEOF(src io.Reader, index uint64) error {
	var extra [1]byte
	n, err := io.ReadFull(src, extra[:])
	if n > 0 {
		return chunkFailure(index, "unexpected data after end-of-stream marker")
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to check end of stream: %w", err)
	}
	return nil
}

// readFrameLen reads the u32be frame length (or terminator) that follows
// chunk index. The input ending here is a structural failure.
func readFrameLen(src io.Reader, index uint64) (uint32, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		if isTruncation(err) {
			return 0, chunkFailure(index, "stream truncated: missing end-of-stream marker after chunk %d", index)
		}
		return 0, fmt.Errorf("chunk %d: failed to read frame length: %w", index, err)
	}
	return binary.BigEndian.Uint32(lenBuf[:]), nil
}

// DecryptStream decrypts a stream body (the bytes after the header MAC) with
// the payload key, following the decoder state machine of
// docs/format-spec.md: it reads frame_i, then the next u32. If it is 0,
// frame_i is opened as final and the input must end; otherwise frame_i is
// opened as non-final and must hold exactly 64 KiB. A stream has at least one
// frame, and when it has more than one, the final frame holds at least one
// plaintext byte (one encoding per plaintext). Truncation at a boundary fails:
// the last kept frame was sealed with final=0.
//
// The caller verifies the header MAC first, so the key is right and every
// failure is tampering: it returns an error wrapping *entities.ChunkAuthError
// with the chunk index (matches entities.ErrHeaderAuthFailed). Plaintext of
// chunks before a failing chunk has already reached dst; callers must discard
// dst on error. aad must match the value passed to the encoder.
func (e *Engine) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte) error {
	gcm, err := newStreamGCM(key)
	if err != nil {
		return err
	}
	minChunkLen := uint32(gcm.Overhead())                   // #nosec G115 -- GCM tag size (16), fits uint32
	maxChunkLen := uint32(streamChunkSize + gcm.Overhead()) // #nosec G115 -- constant, fits uint32

	baseNonce := make([]byte, aesGCMNonceSize)
	if _, err := io.ReadFull(src, baseNonce); err != nil {
		if isTruncation(err) {
			return chunkFailure(0, "stream truncated: failed to read base nonce")
		}
		return fmt.Errorf("failed to read base nonce: %w", err)
	}
	s := newStream(gcm, baseNonce, aad)

	chunkLen, err := readFrameLen(src, 0)
	if err != nil {
		return err
	}
	if chunkLen == 0 {
		return chunkFailure(0, "empty stream: end-of-stream marker before the first chunk")
	}

	sealed := make([]byte, maxChunkLen)
	var plaintext []byte
	for counter := uint64(0); ; counter++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if chunkLen < minChunkLen || chunkLen > maxChunkLen {
			return chunkFailure(counter, "chunk %d: length %d outside [%d, %d]", counter, chunkLen, minChunkLen, maxChunkLen)
		}
		if _, err := io.ReadFull(src, sealed[:chunkLen]); err != nil {
			if isTruncation(err) {
				return chunkFailure(counter, "chunk %d: stream truncated in ciphertext", counter)
			}
			return fmt.Errorf("chunk %d: failed to read ciphertext: %w", counter, err)
		}
		next, err := readFrameLen(src, counter)
		if err != nil {
			return err
		}
		final := next == 0
		if !final && chunkLen != maxChunkLen {
			return chunkFailure(counter, "non-final chunk %d holds %d plaintext bytes, want %d", counter, int(chunkLen)-gcm.Overhead(), streamChunkSize)
		}
		if final && counter > 0 && chunkLen == minChunkLen {
			return chunkFailure(counter, "final chunk %d is empty: only a one-frame stream may end with an empty frame", counter)
		}

		plaintext, err = s.open(plaintext[:0], sealed[:chunkLen], counter, final)
		if err != nil {
			return &entities.ChunkAuthError{Index: counter}
		}
		if _, err := dst.Write(plaintext); err != nil {
			return fmt.Errorf("chunk %d: failed to write plaintext: %w", counter, err)
		}
		if final {
			return requireEOF(src, counter+1)
		}
		chunkLen = next
	}
}
