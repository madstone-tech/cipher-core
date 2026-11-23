package usecases

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

const v2KeyPassphrase = "v2-key-passphrase"

// newWrappedKey returns an Argon2id-wrapped X25519 identity key.
func newWrappedKey(t *testing.T, alias string, isDefault bool, usage int64) *entities.IdentityKey {
	t.Helper()
	engine := cryptoadapter.NewEngine()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	pub, priv, err := engine.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := kekProvider.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := kekProvider.DeriveKEK(v2KeyPassphrase, salt)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := engine.Hash(pub)
	wrapped, err := kekProvider.WrapKey(priv, kek, fingerprint[:16])
	if err != nil {
		t.Fatal(err)
	}
	return &entities.IdentityKey{
		ID: fingerprint[:16], Type: entities.KeyTypeX25519, Alias: alias, Fingerprint: fingerprint,
		PublicKey: pub, WrappedPrivateKey: wrapped, Argon2idSalt: salt, CreatedAt: time.Now(),
		UsageCount: usage, IsDefault: isDefault,
		StorageMode: entities.StorageModeStandard, StorageBackend: entities.StorageBackendSQLite,
	}
}

func newV2Usecases(repo *fakeKeyRepo) (*EncryptFile, *DecryptFile) {
	engine := cryptoadapter.NewEngine()
	encoder := cryptoadapter.NewFileEncoder()
	kekProvider := cryptoadapter.NewArgon2idKEKProvider()
	fh := newFakeFileHandler()
	enc := NewEncryptFile(repo, &fakeRecoveryRepo{}, engine, kekProvider, newFakeSessionStore(), encoder, nil, fh, &fakeProgress{}, &fakePrompter{}, &fakeLogger{})
	dec := NewDecryptFile(repo, engine, kekProvider, newFakeSessionStore(), encoder, fh, &fakeProgress{}, &panicOnPromptPrompter{}, &fakeLogger{})
	return enc, dec
}

func TestTrialKeyOrder(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	a := &entities.IdentityKey{ID: "a", UsageCount: 1}
	b := &entities.IdentityKey{ID: "b", IsDefault: true}
	c := &entities.IdentityKey{ID: "c", UsageCount: 9}
	d := &entities.IdentityKey{ID: "d", UsageCount: 99, ExpiresAt: &past}
	e := &entities.IdentityKey{ID: "e", UsageCount: 1}

	var got []string
	for _, k := range trialKeyOrder([]*entities.IdentityKey{a, b, c, d, e}) {
		got = append(got, k.ID)
	}
	if want := []string{"b", "c", "a", "e"}; !slices.Equal(got, want) {
		t.Errorf("trial order = %v, want %v", got, want)
	}
}

// TestDecryptV2TriesEachLocalKey encrypts for a local key that is not the
// default and checks that DecryptStream finds it by trial unwrap (v2 blocks
// name no recipient), and that a file for a foreign key is ErrNotARecipient.
func TestDecryptV2TriesEachLocalKey(t *testing.T) {
	def := newWrappedKey(t, "default", true, 0)
	other := newWrappedKey(t, "other", false, 3)
	foreign := newWrappedKey(t, "foreign", false, 0)
	repo := &fakeKeyRepo{keys: []*entities.IdentityKey{def, other}}
	enc, dec := newV2Usecases(repo)
	ctx := context.Background()
	plain := make([]byte, 3*65536+17)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	var sealed bytes.Buffer
	if _, err := enc.EncryptStream(ctx, bytes.NewReader(plain), &sealed, &EncryptStreamRequest{
		Recipients:       []Recipient{{PublicKey: other.PublicKey, Fingerprint: other.Fingerprint}},
		OriginalFilename: "x.bin",
	}); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if b := sealed.Bytes(); b[4] != 0x03 {
		t.Fatalf("version byte = %#x, want 0x03", b[4])
	}

	var out bytes.Buffer
	resp, err := dec.DecryptStream(ctx, bytes.NewReader(sealed.Bytes()), &out, &DecryptStreamRequest{RecoveryPassphrase: v2KeyPassphrase})
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) || resp.OriginalFilename != "x.bin" || resp.Method != entities.MethodX25519 {
		t.Fatalf("round trip: %d bytes, resp %+v", out.Len(), resp)
	}
	if other.UsageCount != 4 || def.UsageCount != 0 {
		t.Errorf("usage counts default=%d other=%d, want 0 and 4", def.UsageCount, other.UsageCount)
	}

	sealed.Reset()
	if _, err := enc.EncryptStream(ctx, bytes.NewReader(plain), &sealed, &EncryptStreamRequest{
		Recipients: []Recipient{{PublicKey: foreign.PublicKey}},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = dec.DecryptStream(ctx, bytes.NewReader(sealed.Bytes()), &bytes.Buffer{}, &DecryptStreamRequest{RecoveryPassphrase: v2KeyPassphrase})
	if !errors.Is(err, entities.ErrNotARecipient) {
		t.Fatalf("foreign file: want ErrNotARecipient, got %v", err)
	}
}

// TestPassphraseStreamV2 checks the method-3 stream core: Argon2id header
// fields, round trip, and the wrong-password class.
func TestPassphraseStreamV2(t *testing.T) {
	enc, dec := newV2Usecases(&fakeKeyRepo{})
	ctx := context.Background()
	plain := bytes.Repeat([]byte("v2 stream "), 20000)

	var sealed bytes.Buffer
	if _, err := enc.EncryptStream(ctx, bytes.NewReader(plain), &sealed, &EncryptStreamRequest{Passphrase: "pw"}); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	file, _, err := cryptoadapter.NewFileEncoder().DecodeHeader(bytes.NewReader(sealed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if file.Version != entities.FormatVersion || !file.Chunked || file.KDF != entities.KDFArgon2id ||
		file.KDFParams != entities.FileKDFParams || len(file.Salt) != 16 {
		t.Fatalf("header = %+v", file)
	}

	var out bytes.Buffer
	if _, err := dec.DecryptStream(ctx, bytes.NewReader(sealed.Bytes()), &out, &DecryptStreamRequest{Passphrase: "pw"}); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatal("round trip differs")
	}

	_, err = dec.DecryptStream(ctx, bytes.NewReader(sealed.Bytes()), &bytes.Buffer{}, &DecryptStreamRequest{Passphrase: "wrong"})
	if !errors.Is(err, entities.ErrWrongPassword) || errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Fatalf("wrong password: want ErrWrongPassword only, got %v", err)
	}
}

// TestSingleFrameBodyBound checks that a single-frame body (after a valid
// header MAC) larger than the single-frame threshold is rejected with the
// tamper class without reading past the bound.
func TestSingleFrameBodyBound(t *testing.T) {
	_, dec := newV2Usecases(&fakeKeyRepo{})
	engine := cryptoadapter.NewEngine()
	salt := make([]byte, 16)
	header, err := cryptoadapter.NewFileEncoder().EncodeHeader(&entities.EncryptedFile{
		Version: entities.FormatVersion, Method: entities.MethodPassphrase, Chunked: false,
		Salt: salt, KDF: entities.KDFArgon2id, KDFParams: entities.FileKDFParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := engine.DeriveFileKeyArgon2id("pw", salt)
	if err != nil {
		t.Fatal(err)
	}
	headerMAC, err := engine.HeaderMAC(fileKey, header)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{maxSingleFrameBody, maxSingleFrameBody + 1} {
		src := append(append(append([]byte{}, header...), headerMAC...), make([]byte, size)...)
		_, err := dec.DecryptStream(context.Background(), bytes.NewReader(src), &bytes.Buffer{}, &DecryptStreamRequest{Passphrase: "pw"})
		if !errors.Is(err, entities.ErrHeaderAuthFailed) {
			t.Fatalf("body of %d bytes: err = %v, want ErrHeaderAuthFailed", size, err)
		}
		overBound := size > maxSingleFrameBody
		if gotBound := strings.Contains(err.Error(), "exceeds"); gotBound != overBound {
			t.Errorf("body of %d bytes: err = %v", size, err)
		}
	}
}
