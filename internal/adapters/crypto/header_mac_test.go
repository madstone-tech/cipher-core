package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// silentProgress is a no-op usecases.ProgressReporter.
type silentProgress struct{}

func (silentProgress) ReportProgress(string, int) {}
func (silentProgress) ReportError(error)          {}
func (silentProgress) ReportSuccess(string)       {}

// listKeyRepo is a usecases.KeyRepository that lists fixed keys. The other
// methods are not used by the decrypt paths under test (nil interface).
type listKeyRepo struct {
	usecases.KeyRepository
	keys []*entities.IdentityKey
}

func (r *listKeyRepo) List(context.Context, usecases.KeyFilters) ([]*entities.IdentityKey, error) {
	return r.keys, nil
}

func (r *listKeyRepo) Update(context.Context, *entities.IdentityKey) error { return nil }

// specFileKeys computes the header MAC and the payload key of fileKey from
// docs/format-spec.md with the standard library only (no engine code):
// mac_key = HKDF-SHA256(file_key, info="mdstn-cipher/v2/header-mac"),
// payload_key = HKDF-SHA256(file_key, info="mdstn-cipher/v2/payload"),
// header_mac = HMAC-SHA256(mac_key, headerAAD).
func specFileKeys(t *testing.T, fileKey, headerAAD []byte) (headerMAC, payloadKey []byte) {
	t.Helper()
	derive := func(info string) []byte {
		out := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, fileKey, nil, []byte(info)), out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	mac := hmac.New(sha256.New, derive("mdstn-cipher/v2/header-mac"))
	mac.Write(headerAAD)
	return mac.Sum(nil), derive("mdstn-cipher/v2/payload")
}

// mnemonicKey returns a recovery phrase from fixed entropy and its X25519 key pair.
func mnemonicKey(t *testing.T, seed byte) (phrase string, pub []byte) {
	t.Helper()
	entropy := bytes.Repeat([]byte{seed}, 32)
	phrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err = DeriveX25519FromMnemonic(phrase)
	if err != nil {
		t.Fatal(err)
	}
	return phrase, pub
}

// gf128 is a GF(2^128) element in the GCM bit order: hi holds bytes 0..7 and
// lo bytes 8..15, both big-endian; bit 0 is the most significant bit of byte 0.
type gf128 struct{ hi, lo uint64 }

func gfFromBytes(b []byte) gf128 {
	return gf128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:16])}
}

func (x gf128) bytes() []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, x.hi), x.lo)
}

func (x gf128) add(y gf128) gf128 { return gf128{x.hi ^ y.hi, x.lo ^ y.lo} }

// mul is the GCM multiplication (NIST SP 800-38D, Algorithm 1).
func (x gf128) mul(y gf128) gf128 {
	var z gf128
	v := y
	for i := range 128 {
		var bit uint64
		if i < 64 {
			bit = x.hi >> (63 - i) & 1
		} else {
			bit = x.lo >> (127 - i) & 1
		}
		if bit == 1 {
			z = z.add(v)
		}
		carry := v.lo & 1
		v.lo = v.lo>>1 | v.hi<<63
		v.hi >>= 1
		if carry == 1 {
			v.hi ^= 0xe1 << 56
		}
	}
	return z
}

// inv returns x^(2^128-2), the inverse of a non-zero x.
func (x gf128) inv() gf128 {
	result := gf128{hi: 1 << 63} // the element 1
	sq := x
	for range 127 {
		sq = sq.mul(sq)
		result = result.mul(sq)
	}
	return result
}

// ghash is GHASH_H(aad, ct) of GCM.
func ghash(h gf128, aad, ct []byte) gf128 {
	var y gf128
	absorb := func(data []byte) {
		for len(data) > 0 {
			block := make([]byte, 16)
			n := copy(block, data)
			data = data[n:]
			y = y.add(gfFromBytes(block)).mul(h)
		}
	}
	absorb(aad)
	absorb(ct)
	lengths := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, uint64(len(aad))*8), uint64(len(ct))*8)
	return y.add(gfFromBytes(lengths)).mul(h)
}

// gcmSalamander returns a 32-byte ciphertext and tag that AES-256-GCM opens
// under both k1 and k2 with the same nonce and aad (AES-GCM is not key
// committing). The first ciphertext block is solved for; the second is zero.
func gcmSalamander(t *testing.T, k1, k2, nonce, aad []byte) []byte {
	t.Helper()
	keyParts := func(k []byte) (h, ej0 gf128) {
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 16)
		block.Encrypt(out, make([]byte, 16))
		h = gfFromBytes(out)
		j0 := append(append([]byte{}, nonce...), 0, 0, 0, 1)
		block.Encrypt(out, j0)
		return h, gfFromBytes(out)
	}
	h1, e1 := keyParts(k1)
	h2, e2 := keyParts(k2)

	ct := make([]byte, 32)
	f1, f2 := ghash(h1, aad, ct), ghash(h2, aad, ct)
	// Block 1 of ct has the factor H^3 in GHASH (then block 2, then lengths).
	h1c := h1.mul(h1).mul(h1)
	h2c := h2.mul(h2).mul(h2)
	c1 := e1.add(e2).add(f1).add(f2).mul(h1c.add(h2c).inv())
	copy(ct[:16], c1.bytes())
	tag := e1.add(ghash(h1, aad, ct))
	sealed := append(ct, tag.bytes()...)

	for _, k := range [][]byte{k1, k2} {
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gcm.Open(nil, nonce, sealed, aad); err != nil {
			t.Fatalf("salamander construction does not open under both keys: %v", err)
		}
	}
	return sealed
}

// TestTwoCEKFileFailsWithTamperClass is the V2-1 file: block A wraps CEK1 for
// Alice, block B wraps CEK2 for Bob, the header MAC is made with CEK1, and the
// body is one GCM frame that opens under both payload keys. Without a key
// commitment both recipients would get (different) plaintext. With the header
// MAC, Alice decrypts, and Bob fails with the tamper class before any body
// decryption (no output, nothing read after the MAC).
func TestTwoCEKFileFailsWithTamperClass(t *testing.T) {
	engine := NewEngine()
	alicePhrase, alicePub := mnemonicKey(t, 0x11)
	bobPhrase, bobPub := mnemonicKey(t, 0x22)
	cek1, cek2 := randomKey(t), randomKey(t)

	block := func(cek, pub []byte) entities.RecipientBlock {
		return v2RecipientBlocks(t, engine, cek, pub)[0]
	}
	header, err := NewFileEncoder().EncodeHeader(&entities.EncryptedFile{
		Version: formatV2, Method: entities.MethodX25519, Chunked: false,
		Recipients:  []entities.RecipientBlock{block(cek1, alicePub), block(cek2, bobPub)},
		EncryptedAt: time.Unix(1793750400, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	mac1, payload1 := specFileKeys(t, cek1, header)
	_, payload2 := specFileKeys(t, cek2, header)
	nonce := bytes.Repeat([]byte{0x5a}, aesGCMNonceSize)
	sealed := gcmSalamander(t, payload1, payload2, nonce, header)

	container := append(append(append(append([]byte{}, header...), mac1...), nonce...), sealed...)

	decrypt := func(phrase string) (*countingReader, *bytes.Buffer, error) {
		repo := &listKeyRepo{keys: []*entities.IdentityKey{{ID: "local", Type: entities.KeyTypeX25519}}}
		uc := usecases.NewDecryptFile(repo, engine, NewArgon2idKEKProvider(), nil, NewFileEncoder(), nil, silentProgress{}, nil, nil)
		src := &countingReader{r: bytes.NewReader(container)}
		var out bytes.Buffer
		_, err := uc.DecryptStream(context.Background(), src, &out, &usecases.DecryptStreamRequest{RecoveryPassphrase: phrase})
		return src, &out, err
	}

	if _, out, err := decrypt(alicePhrase); err != nil {
		t.Fatalf("Alice (the MAC key holder): %v", err)
	} else if out.Len() != 32 {
		t.Fatalf("Alice plaintext is %d bytes, want 32", out.Len())
	}

	src, out, err := decrypt(bobPhrase)
	if !errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Fatalf("Bob: err = %v, want ErrHeaderAuthFailed", err)
	}
	if errors.Is(err, entities.ErrNotARecipient) {
		t.Errorf("Bob: a block that unwraps and fails the MAC must not be ErrNotARecipient: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("Bob: %d plaintext bytes written, want 0", out.Len())
	}
	if want := len(header) + 32; src.n != want {
		t.Errorf("Bob: %d bytes read, want %d (header + MAC, no body)", src.n, want)
	}
}

// TestWrongPasswordFailsBeforeTheBody checks FR-003 and the US1 scenario 6
// for method 3: a wrong password fails with ErrWrongPassword after reading the
// header and the header MAC only; the right password with a damaged body
// fails with the tamper class.
func TestWrongPasswordFailsBeforeTheBody(t *testing.T) {
	engine, encoder := NewEngine(), NewFileEncoder()
	enc := usecases.NewEncryptFile(nil, nil, engine, NewArgon2idKEKProvider(), nil, encoder, nil, nil, silentProgress{}, nil, nil)
	plain := patternPlaintext(3*streamChunkSize + 7)
	var sealed bytes.Buffer
	if _, err := enc.EncryptStream(context.Background(), bytes.NewReader(plain), &sealed, &usecases.EncryptStreamRequest{Passphrase: "right"}); err != nil {
		t.Fatal(err)
	}
	_, headerAAD, err := encoder.DecodeHeader(bytes.NewReader(sealed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	dec := usecases.NewDecryptFile(nil, engine, NewArgon2idKEKProvider(), nil, encoder, nil, silentProgress{}, nil, nil)
	decrypt := func(data []byte, password string) (int, int, error) {
		src := &countingReader{r: bytes.NewReader(data)}
		var out bytes.Buffer
		_, err := dec.DecryptStream(context.Background(), src, &out, &usecases.DecryptStreamRequest{Passphrase: password})
		return src.n, out.Len(), err
	}

	read, written, err := decrypt(sealed.Bytes(), "wrong")
	if !errors.Is(err, entities.ErrWrongPassword) || errors.Is(err, entities.ErrHeaderAuthFailed) {
		t.Fatalf("wrong password: err = %v, want ErrWrongPassword only", err)
	}
	if want := len(headerAAD) + 32; read != want || written != 0 {
		t.Errorf("wrong password: read %d bytes, wrote %d; want read %d (header + MAC), wrote 0", read, written, want)
	}

	damaged := append([]byte{}, sealed.Bytes()...)
	damaged[len(headerAAD)+32+aesGCMNonceSize+4+100] ^= 0x01 // chunk 0 ciphertext
	if _, _, err := decrypt(damaged, "right"); !errors.Is(err, entities.ErrHeaderAuthFailed) || errors.Is(err, entities.ErrWrongPassword) {
		t.Errorf("right password, damaged chunk 0: err = %v, want ErrHeaderAuthFailed only", err)
	}

	if _, written, err := decrypt(sealed.Bytes(), "right"); err != nil || written != len(plain) {
		t.Errorf("right password: wrote %d bytes, err %v; want %d bytes", written, err, len(plain))
	}
}
