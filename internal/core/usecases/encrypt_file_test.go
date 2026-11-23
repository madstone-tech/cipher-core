package usecases

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeKeyRepo is an in-memory KeyRepository.
type fakeKeyRepo struct {
	keys        []*entities.IdentityKey
	createCalls int
	updateCalls int
}

func (r *fakeKeyRepo) Create(_ context.Context, key *entities.IdentityKey) error {
	r.createCalls++
	r.keys = append(r.keys, key)
	return nil
}

func (r *fakeKeyRepo) GetByID(_ context.Context, id string) (*entities.IdentityKey, error) {
	for _, k := range r.keys {
		if k.ID == id {
			return k, nil
		}
	}
	return nil, entities.ErrNotFound
}

func (r *fakeKeyRepo) GetByFingerprint(_ context.Context, fp string) (*entities.IdentityKey, error) {
	for _, k := range r.keys {
		if k.Fingerprint == fp {
			return k, nil
		}
	}
	return nil, entities.ErrNotFound
}

func (r *fakeKeyRepo) GetDefault(_ context.Context) (*entities.IdentityKey, error) {
	for _, k := range r.keys {
		if k.IsDefault {
			return k, nil
		}
	}
	return nil, entities.ErrNotFound
}

func (r *fakeKeyRepo) List(_ context.Context, _ KeyFilters) ([]*entities.IdentityKey, error) {
	return r.keys, nil
}

func (r *fakeKeyRepo) ListMetadata(_ context.Context, _ KeyFilters) ([]*entities.KeyMetadata, error) {
	out := make([]*entities.KeyMetadata, len(r.keys))
	for i, k := range r.keys {
		out[i] = metadataOf(k)
	}
	return out, nil
}

// metadataOf projects an IdentityKey to its blob-free metadata — mirrors the
// repo SQL column lists.
func metadataOf(k *entities.IdentityKey) *entities.KeyMetadata {
	return &entities.KeyMetadata{
		ID:          k.ID,
		UserID:      k.UserID,
		Type:        k.Type,
		Alias:       k.Alias,
		Fingerprint: k.Fingerprint,
		PublicKey:   k.PublicKey,
		StorageMode: k.StorageMode,
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
		UsageCount:  k.UsageCount,
		IsDefault:   k.IsDefault,
	}
}

func (r *fakeKeyRepo) Update(_ context.Context, key *entities.IdentityKey) error {
	r.updateCalls++
	for i, k := range r.keys {
		if k.ID == key.ID {
			r.keys[i] = key
			return nil
		}
	}
	return entities.ErrNotFound
}

func (r *fakeKeyRepo) Delete(_ context.Context, id string) error {
	for i, k := range r.keys {
		if k.ID == id {
			r.keys = append(r.keys[:i], r.keys[i+1:]...)
			return nil
		}
	}
	return entities.ErrNotFound
}
func (r *fakeKeyRepo) Count(_ context.Context) (int, error) { return len(r.keys), nil }

func (r *fakeKeyRepo) ListWithExpiry(_ context.Context) ([]*entities.IdentityKey, error) {
	var out []*entities.IdentityKey
	for _, k := range r.keys {
		if k.ExpiresAt != nil {
			out = append(out, k)
		}
	}
	return out, nil
}

// fakeFileHandler is an in-memory FileHandler.
type fakeFileHandler struct {
	files map[string][]byte
}

func newFakeFileHandler() *fakeFileHandler {
	return &fakeFileHandler{files: make(map[string][]byte)}
}

func (h *fakeFileHandler) ReadFile(path string) ([]byte, error) {
	data, ok := h.files[path]
	if !ok {
		return nil, errors.New("file not found: " + path)
	}
	return data, nil
}

func (h *fakeFileHandler) WriteFile(path string, data []byte) error {
	h.files[path] = data
	return nil
}

func (h *fakeFileHandler) ReadStream(path string) (io.ReadCloser, error) {
	data, ok := h.files[path]
	if !ok {
		return nil, errors.New("file not found: " + path)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (h *fakeFileHandler) WriteStream(path string) (StagedWriter, error) {
	return &fakeWriteCloser{handler: h, path: path}, nil
}

func (h *fakeFileHandler) WriteStreamExclusive(path string) (StagedWriter, error) {
	return &fakeWriteCloser{handler: h, path: path, exclusive: true}, nil
}

func (h *fakeFileHandler) SameFile(a, b string) (bool, error) {
	_, ok := h.files[filepath.Clean(a)]
	return ok && filepath.Clean(a) == filepath.Clean(b), nil
}
func (h *fakeFileHandler) IsDir(_ string) (bool, error)            { return false, nil }
func (h *fakeFileHandler) ResolvePath(path string) (string, error) { return path, nil }
func (h *fakeFileHandler) DirHoldsLink(_, _ string) (bool, error)  { return false, nil }
func (h *fakeFileHandler) Exists(path string) (bool, error) {
	_, ok := h.files[path]
	return ok, nil
}
func (h *fakeFileHandler) CleanupStaleTempFiles(_ string) error { return nil }

// fakeWriteCloser is an in-memory StagedWriter: bytes reach handler.files
// only on Commit, following the data-model.md §StagedWriter state table.
type fakeWriteCloser struct {
	handler   *fakeFileHandler
	path      string
	buf       bytes.Buffer
	committed bool
	aborted   bool
	exclusive bool
}

var errFakeWriterClosed = errors.New("fake staged writer is closed")

func (w *fakeWriteCloser) Write(p []byte) (int, error) {
	if w.committed || w.aborted {
		return 0, errFakeWriterClosed
	}
	return w.buf.Write(p)
}

func (w *fakeWriteCloser) Commit() error {
	switch {
	case w.committed:
		return nil
	case w.aborted:
		return errFakeWriterClosed
	}
	if _, exists := w.handler.files[w.path]; exists && w.exclusive {
		w.aborted = true
		return fmt.Errorf("output %s: %w", w.path, fs.ErrExist)
	}
	w.committed = true
	w.handler.files[w.path] = w.buf.Bytes()
	return nil
}

func (w *fakeWriteCloser) Abort() error {
	if !w.committed {
		w.aborted = true
		w.buf.Reset()
	}
	return nil
}

// fakeProgress is a no-op ProgressReporter.
type fakeProgress struct{}

func (p *fakeProgress) ReportProgress(_ string, _ int) {}
func (p *fakeProgress) ReportError(_ error)            {}
func (p *fakeProgress) ReportSuccess(_ string)         {}

// fakeRecoveryRepo is an in-memory RecoveryKeyRepository.
type fakeRecoveryRepo struct {
	keys []*entities.RecoveryKey
}

func (r *fakeRecoveryRepo) Create(_ context.Context, rk *entities.RecoveryKey) error {
	r.keys = append(r.keys, rk)
	return nil
}

func (r *fakeRecoveryRepo) Get(_ context.Context) (*entities.RecoveryKey, error) {
	if len(r.keys) == 0 {
		return nil, entities.ErrNotFound
	}
	return r.keys[0], nil
}

func (r *fakeRecoveryRepo) Count(_ context.Context) (int, error) {
	return len(r.keys), nil
}

// fakePrompter always answers "yes" (for recovery confirmation in tests).
type fakePrompter struct{}

func (p *fakePrompter) PromptString(_ string) (string, error)     { return "yes", nil }
func (p *fakePrompter) PromptConfirm(_ string) (bool, error)      { return true, nil }
func (p *fakePrompter) PromptPassphrase(_ string) (string, error) { return "", nil }

// fakeLogger is a no-op Logger.
type fakeLogger struct{}

func (l *fakeLogger) Debug(_ string, _ map[string]interface{})   {}
func (l *fakeLogger) Info(_ string, _ map[string]interface{})    {}
func (l *fakeLogger) Warn(_ string, _ map[string]interface{})    {}
func (l *fakeLogger) Error(_ string, _ map[string]interface{})   {}
func (l *fakeLogger) WithFields(_ map[string]interface{}) Logger { return l }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestEncryptFile(repo *fakeKeyRepo, fh *fakeFileHandler) *EncryptFile {
	crypto := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	recoveryRepo := &fakeRecoveryRepo{}
	return NewEncryptFile(repo, recoveryRepo, crypto, nil, nil, encoder, nil, fh, &fakeProgress{}, &fakePrompter{}, &fakeLogger{})
}

// recordingProgress is a ProgressReporter that keeps the success messages.
type recordingProgress struct {
	fakeProgress
	successes []string
}

func (p *recordingProgress) ReportSuccess(message string) {
	p.successes = append(p.successes, message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCreateDefaultKey_StoresX25519Key verifies the auto-created key is X25519.
func TestCreateDefaultKey_StoresX25519Key(t *testing.T) {
	repo := &fakeKeyRepo{}
	uc := newTestEncryptFile(repo, newFakeFileHandler())

	key, _, err := uc.createDefaultKey(context.Background(), true)
	if err != nil {
		t.Fatalf("createDefaultKey returned error: %v", err)
	}

	// Type
	if key.Type != entities.KeyTypeX25519 {
		t.Errorf("key.Type = %q, want %q", key.Type, entities.KeyTypeX25519)
	}
	// Public and private key sizes
	if len(key.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32", len(key.PublicKey))
	}
	if len(key.WrappedPrivateKey) != 32 {
		t.Errorf("WrappedPrivateKey length = %d, want 32", len(key.WrappedPrivateKey))
	}
	// Alias and default flag
	if key.Alias != "default" {
		t.Errorf("key.Alias = %q, want \"default\"", key.Alias)
	}
	if !key.IsDefault {
		t.Error("key.IsDefault = false, want true")
	}
	// Fingerprint is derived from public key
	crypto := cryptoadapter.NewEngine()
	wantFP := crypto.Hash(key.PublicKey)
	if key.Fingerprint != wantFP {
		t.Errorf("key.Fingerprint = %q, want %q", key.Fingerprint, wantFP)
	}
	// ID is first 16 chars of fingerprint
	if key.ID != key.Fingerprint[:16] {
		t.Errorf("key.ID = %q, want %q", key.ID, key.Fingerprint[:16])
	}
	// Persisted in repo
	if repo.createCalls != 1 {
		t.Errorf("repo.Create called %d times, want 1", repo.createCalls)
	}
}

// TestCreateDefaultKey_PrintsConfirmation verifies that the first-run
// confirmation goes to the progress reporter, not to stdout.
func TestCreateDefaultKey_PrintsConfirmation(t *testing.T) {
	repo := &fakeKeyRepo{}
	uc := newTestEncryptFile(repo, newFakeFileHandler())
	progress := &recordingProgress{}
	uc.progress = progress

	key, _, err := uc.createDefaultKey(context.Background(), true)
	if err != nil {
		t.Fatalf("createDefaultKey error: %v", err)
	}
	output := strings.Join(progress.successes, "\n")

	if key == nil {
		t.Fatal("key is nil")
	}

	// Must contain the confirmation prefix
	wantPrefix := "Created default encryption key (fingerprint: "
	if !strings.Contains(output, wantPrefix) {
		t.Errorf("progress %q does not contain %q", output, wantPrefix)
	}
	// Must contain 8-char fingerprint prefix followed by "..."
	fp8 := key.Fingerprint[:8]
	wantSuffix := fp8 + "...)"
	if !strings.Contains(output, wantSuffix) {
		t.Errorf("progress %q does not contain %q", output, wantSuffix)
	}
}

// TestEncryptForSelf_ZeroConfig_FirstRun verifies first-run auto-creation and encryption.
func TestEncryptForSelf_ZeroConfig_FirstRun(t *testing.T) {
	repo := &fakeKeyRepo{}
	fh := newFakeFileHandler()

	// Write a real temp file so os.Stat succeeds; ReadFile is served by fakeFileHandler.
	dir := t.TempDir()
	inputPath := dir + "/input.txt"
	if err := os.WriteFile(inputPath, []byte("hello zero-config world"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fh.files[inputPath] = []byte("hello zero-config world")

	uc := newTestEncryptFile(repo, fh)

	resp, err := uc.Execute(context.Background(), &EncryptFileRequest{
		FilePath:   inputPath,
		JSONOutput: true,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// One key auto-created
	if repo.createCalls != 1 {
		t.Errorf("repo.Create called %d times, want 1", repo.createCalls)
	}
	// Method is X25519
	if resp.Method != entities.MethodX25519 {
		t.Errorf("resp.Method = %q, want %q", resp.Method, entities.MethodX25519)
	}
	// Output file written (in-memory)
	outputPath := inputPath + ".mdstn"
	if _, ok := fh.files[outputPath]; !ok {
		t.Errorf("output file %q not found in fake handler", outputPath)
	}
}

// TestEncryptForSelf_SecondRun_ReusesKey verifies no new key is generated on second run.
func TestEncryptForSelf_SecondRun_ReusesKey(t *testing.T) {
	repo := &fakeKeyRepo{}
	fh := newFakeFileHandler()

	dir := t.TempDir()
	inputPath := dir + "/reuse.txt"
	content := []byte("reuse test")
	if err := os.WriteFile(inputPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fh.files[inputPath] = content

	uc := newTestEncryptFile(repo, fh)

	// First run — auto-creates key
	_, err := uc.Execute(context.Background(), &EncryptFileRequest{FilePath: inputPath, JSONOutput: true})
	if err != nil {
		t.Fatalf("first Execute error: %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("after first run: repo.Create called %d times, want 1", repo.createCalls)
	}

	// Second run — must reuse the existing key. Overwrite: the first run's
	// default output exists.
	_, err = uc.Execute(context.Background(), &EncryptFileRequest{FilePath: inputPath, JSONOutput: true, Overwrite: true})
	if err != nil {
		t.Fatalf("second Execute error: %v", err)
	}
	if repo.createCalls != 1 {
		t.Errorf("after second run: repo.Create called %d times, want still 1", repo.createCalls)
	}
}

// TestEncryptForSelf_V2_RoundTrip verifies small-file encrypt→decrypt round-trip.
func TestEncryptForSelf_V2_RoundTrip(t *testing.T) {
	repo := &fakeKeyRepo{}
	fh := newFakeFileHandler()

	plaintext := []byte("round trip plaintext data — feature 005")
	dir := t.TempDir()
	inputPath := dir + "/roundtrip.txt"
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fh.files[inputPath] = plaintext

	uc := newTestEncryptFile(repo, fh)

	_, err := uc.Execute(context.Background(), &EncryptFileRequest{FilePath: inputPath, JSONOutput: true})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Retrieve the auto-created key
	if len(repo.keys) == 0 {
		t.Fatal("no keys in repo after encrypt")
	}
	key := repo.keys[0]

	// Decode the output file
	outputPath := inputPath + ".mdstn"
	encoded, ok := fh.files[outputPath]
	if !ok {
		t.Fatalf("output file %q not found", outputPath)
	}

	encoder := cryptoadapter.NewFileEncoder()
	encFile, _, offset, err := encoder.DecodeWithOffset(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if encFile.Version != entities.FormatVersion || encoded[4] != 0x03 {
		t.Errorf("version = %d (byte 4 = %#x), want 3", encFile.Version, encoded[4])
	}
	if encFile.Method != entities.MethodX25519 {
		t.Errorf("encFile.Method = %q, want %q", encFile.Method, entities.MethodX25519)
	}
	if encFile.Chunked {
		t.Errorf("chunked = true, want false (small file under threshold)")
	}
	if len(encFile.Recipients) != 1 {
		t.Fatalf("want one recipient block; got %+v", encFile)
	}

	// Body: [header_mac(32)][body_nonce(12)][single frame]; header bytes are AAD.
	headerAAD := encoded[:offset]
	body := encoded[offset:]
	if len(body) < entities.HeaderMACSize+12 {
		t.Fatalf("body too short: %d", len(body))
	}
	headerMAC, bodyNonce, bodyCT := body[:entities.HeaderMACSize], body[entities.HeaderMACSize:entities.HeaderMACSize+12], body[entities.HeaderMACSize+12:]

	// Unwrap the CEK from the single recipient block, check the header MAC,
	// and open the body with the payload key.
	crypto := cryptoadapter.NewEngine()
	block := encFile.Recipients[0]
	eph, _ := base64.StdEncoding.DecodeString(block.EphemeralPubKey)
	nonce, _ := base64.StdEncoding.DecodeString(block.Nonce)
	wrapped, _ := base64.StdEncoding.DecodeString(block.WrappedCEK)
	cek, err := crypto.UnwrapCEK(wrapped, eph, nonce, key.WrappedPrivateKey, []byte(entities.WrapCEKAAD))
	if err != nil {
		t.Fatalf("CEK unwrap error: %v", err)
	}
	if ok, err := crypto.VerifyHeaderMAC(cek, headerAAD, headerMAC); err != nil || !ok {
		t.Fatalf("header MAC: ok=%v err=%v", ok, err)
	}
	payloadKey, err := crypto.DerivePayloadKey(cek)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := crypto.DecryptAES(bodyCT, payloadKey, bodyNonce, headerAAD)
	if err != nil {
		t.Fatalf("body decrypt error: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("decrypted = %q, want %q", recovered, plaintext)
	}
}
