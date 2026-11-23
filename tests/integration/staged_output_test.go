package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

const (
	stagedTestPassphrase = "staged-output-passphrase"
	// streamChunk is the stream plaintext chunk size.
	streamChunk = 64 << 10
	// streamFrameSize is one non-final format v2 frame: u32 len | ct(64 KiB) | tag(16).
	streamFrameSize = 4 + streamChunk + 16
)

// sourceHook wraps the real cli.FileHandler and lets a test intercept the
// reader returned by ReadStream. WriteStream/WriteFile are the real staging.
type sourceHook struct {
	*cli.FileHandler
	wrap func(path string, rc io.ReadCloser) io.ReadCloser
}

func (h *sourceHook) ReadStream(path string) (io.ReadCloser, error) {
	rc, err := h.FileHandler.ReadStream(path)
	if err != nil || h.wrap == nil {
		return rc, err
	}
	return h.wrap(path, rc), nil
}

// hookReader runs onLimit once, after limit bytes have been read, and then
// returns failErr (if non-nil) from every later Read.
type hookReader struct {
	rc      io.ReadCloser
	limit   int
	read    int
	onLimit func()
	failErr error
	fired   bool
}

func (r *hookReader) Read(p []byte) (int, error) {
	if r.fired && r.failErr != nil {
		return 0, r.failErr
	}
	if remaining := r.limit - r.read; !r.fired && len(p) > remaining {
		p = p[:remaining]
	}
	n, err := r.rc.Read(p)
	r.read += n
	if !r.fired && r.read >= r.limit {
		r.fired = true
		if r.onLimit != nil {
			r.onLimit()
		}
	}
	return n, err
}

func (r *hookReader) Close() error { return r.rc.Close() }

// stagedEnv wires EncryptFile/DecryptFile over a sourceHook.
type stagedEnv struct {
	dir     string
	files   *sourceHook
	encrypt *usecases.EncryptFile
	decrypt *usecases.DecryptFile
}

func newStagedEnv(t *testing.T) *stagedEnv {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	keyRepo, err := sqlite.NewIdentityKeyRepository(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewIdentityKeyRepository: %v", err)
	}
	t.Cleanup(func() {
		if err := keyRepo.Close(); err != nil {
			t.Errorf("close key repo: %v", err)
		}
	})
	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())
	cryptoEngine := crypto.NewEngine()
	encoder := crypto.NewFileEncoder()
	logger := logging.NewSimpleLogger()
	kekProvider := crypto.NewArgon2idKEKProvider()
	sessionStore := crypto.NewInMemorySessionStore(ctx)
	t.Cleanup(sessionStore.Stop)
	lookupKeyUC := usecases.NewLookupKey(ckd.NewClient(ckdCache), ckdCache, logger)

	files := &sourceHook{FileHandler: cli.NewFileHandler()}
	return &stagedEnv{
		dir:   dir,
		files: files,
		encrypt: usecases.NewEncryptFile(keyRepo, recoveryRepo, cryptoEngine, kekProvider, sessionStore,
			encoder, lookupKeyUC, files, &noopProgress{}, &yesPrompter{}, logger),
		decrypt: usecases.NewDecryptFile(keyRepo, cryptoEngine, kekProvider, sessionStore,
			encoder, files, &noopProgress{}, &noopPrompter{}, logger),
	}
}

// writeRandom writes size random bytes to dir/name and returns the path and data.
func (e *stagedEnv) writeRandom(t *testing.T, name string, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	path := filepath.Join(e.dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return path, data
}

// encryptFile encrypts src with the test passphrase and returns the .mdstn path.
func (e *stagedEnv) encryptFile(ctx context.Context, t *testing.T, src string) string {
	t.Helper()
	resp, err := e.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return resp.OutputPath
}

// assertNoOutput fails if path exists or any staged partial remains in its directory.
func assertNoOutput(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file exists at output path %s (Lstat err = %v)", path, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".mdstn-partial") || strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("staged file left behind: %s", entry.Name())
		}
	}
}

// streamBodyOffset returns the offset of the stream body (base nonce) in an
// encrypted file: after the header and the header MAC.
func streamBodyOffset(t *testing.T, enc []byte) int64 {
	t.Helper()
	encFile, _, offset, err := crypto.NewFileEncoder().DecodeWithOffset(enc)
	if err != nil {
		t.Fatalf("DecodeWithOffset: %v", err)
	}
	if !encFile.Chunked {
		t.Fatal("fixture is not chunked; want the stream framing")
	}
	return offset + entities.HeaderMACSize
}

// TestStagedOutputTamperedChunkLeavesNoFile flips one ciphertext bit in chunk
// 10 of a 20-chunk stream. Chunks 0-9 decrypt before the failure, so without
// staging their plaintext would be published at the output path.
func TestStagedOutputTamperedChunkLeavesNoFile(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	src, _ := env.writeRandom(t, "twenty.bin", 20*streamChunk)
	encPath := env.encryptFile(ctx, t, src)

	enc, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	pos := streamBodyOffset(t, enc) + 12 + 10*streamFrameSize + 4 + 100
	enc[pos] ^= 0x01
	if err := os.WriteFile(encPath, enc, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	outPath := filepath.Join(env.dir, "twenty.out")
	_, err = env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath: encPath, OutputPath: outPath, Passphrase: stagedTestPassphrase,
	})
	if err == nil {
		t.Fatal("decrypt of tampered stream succeeded")
	}
	if !errors.Is(err, entities.ErrHeaderAuthFailed) || errors.Is(err, entities.ErrWrongPassword) {
		t.Errorf("error class: Is(HeaderAuthFailed)=%v Is(WrongPassword)=%v, want true/false; err = %v",
			errors.Is(err, entities.ErrHeaderAuthFailed), errors.Is(err, entities.ErrWrongPassword), err)
	}
	var chunkErr *entities.ChunkAuthError
	if !errors.As(err, &chunkErr) || chunkErr.Index != 10 {
		t.Errorf("want ChunkAuthError{Index: 10}; err = %v", err)
	}
	assertNoOutput(t, outPath)
}

// TestStagedOutputEncryptSourceFailureLeavesNoFile fails the source reader
// mid-stream; the partially written .mdstn must not be published.
func TestStagedOutputEncryptSourceFailureLeavesNoFile(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	src, _ := env.writeRandom(t, "source.bin", 2<<20)
	errSource := errors.New("injected source failure")
	env.files.wrap = func(_ string, rc io.ReadCloser) io.ReadCloser {
		return &hookReader{rc: rc, limit: 5 * streamChunk, failErr: errSource}
	}

	_, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
	if !errors.Is(err, errSource) {
		t.Fatalf("encrypt error = %v, want the injected source failure", err)
	}
	assertNoOutput(t, src+".mdstn")
}

// TestStagedOutputCancellationLeavesNoFile cancels the context part-way
// through a 5 MiB encryption and a 5 MiB decryption.
func TestStagedOutputCancellationLeavesNoFile(t *testing.T) {
	const size = 5 << 20

	t.Run("encrypt", func(t *testing.T) {
		env := newStagedEnv(t)
		src, _ := env.writeRandom(t, "five.bin", size)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env.files.wrap = func(_ string, rc io.ReadCloser) io.ReadCloser {
			return &hookReader{rc: rc, limit: size / 2, onLimit: cancel}
		}

		_, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("encrypt error = %v, want context.Canceled", err)
		}
		assertNoOutput(t, src+".mdstn")
	})

	t.Run("decrypt", func(t *testing.T) {
		env := newStagedEnv(t)
		src, _ := env.writeRandom(t, "five.bin", size)
		encPath := env.encryptFile(context.Background(), t, src)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env.files.wrap = func(_ string, rc io.ReadCloser) io.ReadCloser {
			return &hookReader{rc: rc, limit: size / 2, onLimit: cancel}
		}

		outPath := filepath.Join(env.dir, "five.out")
		_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
			FilePath: encPath, OutputPath: outPath, Passphrase: stagedTestPassphrase,
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("decrypt error = %v, want context.Canceled", err)
		}
		assertNoOutput(t, outPath)
	})
}

// TestPassphraseWrongPasswordClass checks FR-003: a wrong password fails the
// header MAC and gives ErrWrongPassword (and not ErrHeaderAuthFailed) with the
// same message for the single-frame (1 KiB) and the stream (2 MiB) framing,
// and leaves no output.
func TestPassphraseWrongPasswordClass(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	messages := map[string]string{}
	for name, size := range map[string]int{"single-frame": 1 << 10, "stream": 2 << 20} {
		src, _ := env.writeRandom(t, name+".bin", size)
		encPath := env.encryptFile(ctx, t, src)

		outPath := filepath.Join(env.dir, name+".out")
		_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
			FilePath: encPath, OutputPath: outPath, Passphrase: "not-the-password",
		})
		if err == nil {
			t.Fatalf("%s: decrypt with a wrong password succeeded", name)
		}
		if !errors.Is(err, entities.ErrWrongPassword) {
			t.Errorf("%s: errors.Is(err, ErrWrongPassword) = false; err = %v", name, err)
		}
		if errors.Is(err, entities.ErrHeaderAuthFailed) {
			t.Errorf("%s: errors.Is(err, ErrHeaderAuthFailed) = true, want false; err = %v", name, err)
		}
		var chunkErr *entities.ChunkAuthError
		if errors.As(err, &chunkErr) {
			t.Errorf("%s: a wrong password fails the header MAC, not a chunk; err = %v", name, err)
		}
		messages[name] = err.Error()
		assertNoOutput(t, outPath)
	}
	if messages["single-frame"] != messages["stream"] {
		t.Errorf("messages differ:\n single-frame: %q\n stream:       %q", messages["single-frame"], messages["stream"])
	}
}

// splitStreamV2 splits an encrypted stream file into the bytes before the
// first frame (header, header MAC, and base nonce) and the frames
// (u32 len | ct), without the terminator.
func splitStreamV2(t *testing.T, enc []byte) (head []byte, frames [][]byte) {
	t.Helper()
	if enc[4] != 0x03 {
		t.Fatalf("version byte = %#x, want 0x03", enc[4])
	}
	p := int(streamBodyOffset(t, enc)) + 12
	head = enc[:p]
	for {
		n := int(binary.BigEndian.Uint32(enc[p : p+4]))
		if n == 0 {
			if p+4 != len(enc) {
				t.Fatalf("%d bytes after the terminator", len(enc)-p-4)
			}
			return head, frames
		}
		frames = append(frames, enc[p:p+4+n])
		p += 4 + n
	}
}

// joinStream returns head || frames || (terminator if term).
func joinStream(head []byte, term bool, frames ...[]byte) []byte {
	out := append([]byte{}, head...)
	for _, f := range frames {
		out = append(out, f...)
	}
	if term {
		out = append(out, 0, 0, 0, 0)
	}
	return out
}

// TestPassphraseStreamReviewCasesAreTamper runs the frame-level changes of the
// review (swap, dup, remove, trunc, lateflip, forged length) plus truncation
// without a terminator and trailing bytes on a new 1.25 MiB password file.
// Each must be tamper (exit 2) with the correct password, not a wrong
// password, and leave no output: the header MAC proves the key before the
// body. A version byte 0x03 → 0x01 is "unsupported version" (exit 1).
func TestPassphraseStreamReviewCasesAreTamper(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	src, data := env.writeRandom(t, "review.bin", 20*streamChunk)
	encPath := env.encryptFile(ctx, t, src)
	enc, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	head, f := splitStreamV2(t, enc)
	if len(f) != 20 {
		t.Fatalf("%d frames, want 20", len(f))
	}

	swapped := append([][]byte{f[1], f[0]}, f[2:]...)
	dup := make([][]byte, 20)
	for i := range dup {
		dup[i] = f[0]
	}
	removed := append(append([][]byte{}, f[:5]...), f[6:]...)
	lateflip := append([]byte{}, enc...)
	lateflip[len(head)+10*streamFrameSize+4+100] ^= 0x01
	forged := append([]byte{}, f[1]...)
	binary.BigEndian.PutUint32(forged[:4], 0xFFFFFFF0)
	versionFlip := append([]byte{}, enc...)
	versionFlip[4] = 0x01
	t.Run("version byte 0x03 -> 0x01", func(t *testing.T) {
		path := filepath.Join(env.dir, "retired.mdstn")
		if err := os.WriteFile(path, versionFlip, 0o600); err != nil {
			t.Fatal(err)
		}
		outPath := filepath.Join(env.dir, "retired.out")
		_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: path, OutputPath: outPath, Passphrase: stagedTestPassphrase})
		if err == nil || !strings.Contains(err.Error(), "unsupported version") || errors.Is(err, entities.ErrHeaderAuthFailed) || errors.Is(err, entities.ErrWrongPassword) {
			t.Fatalf("want unsupported version (parse error); err = %v", err)
		}
		assertNoOutput(t, outPath)
	})

	cases := map[string][]byte{
		"swap frames 0 and 1":       joinStream(head, true, swapped...),
		"dup frame 0":               joinStream(head, true, dup...),
		"remove frame 0":            joinStream(head, true, f[1:]...),
		"remove middle frame":       joinStream(head, true, removed...),
		"trunc + terminator":        joinStream(head, true, f[:3]...),
		"trunc without terminator":  joinStream(head, false, f[:3]...),
		"lateflip (chunk 10 of 20)": lateflip,
		"forged length":             joinStream(head, true, f[0], forged),
		"bytes after terminator":    append(append([]byte{}, enc...), 0xAA),
	}
	for name, tampered := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(env.dir, "tampered.mdstn")
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			outPath := filepath.Join(env.dir, "tampered.out")
			_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
				FilePath: path, OutputPath: outPath, Passphrase: stagedTestPassphrase,
			})
			if !errors.Is(err, entities.ErrHeaderAuthFailed) || errors.Is(err, entities.ErrWrongPassword) {
				t.Fatalf("want ErrHeaderAuthFailed only; err = %v", err)
			}
			assertNoOutput(t, outPath)
		})
	}

	t.Run("unchanged", func(t *testing.T) {
		outPath := filepath.Join(env.dir, "review.out")
		if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
			FilePath: encPath, OutputPath: outPath, Passphrase: stagedTestPassphrase,
		}); err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Error("round-trip output differs from the source")
		}
	})
}

// TestStagedOutputRoundTrip checks that the staged path still publishes a
// byte-identical result.
func TestStagedOutputRoundTrip(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	src, data := env.writeRandom(t, "ok.bin", 20*streamChunk+123)
	encPath := env.encryptFile(ctx, t, src)
	outPath := filepath.Join(env.dir, "ok.out")
	if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{
		FilePath: encPath, OutputPath: outPath, Passphrase: stagedTestPassphrase,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round-trip output differs from the source")
	}
}
