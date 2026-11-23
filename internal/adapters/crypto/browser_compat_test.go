package crypto_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	localcrypto "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// TestIndependentEncoderInterop builds a method-2 stream file the way a
// second implementation (for example the browser encoder) would, from
// docs/format-spec.md and the standard library only: header JSON, recipient
// block, header MAC, payload key, and STREAM frames. The production decoder
// must decrypt it.
func TestIndependentEncoderInterop(t *testing.T) {
	phrase := "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware"
	recipientPub, _, err := localcrypto.DeriveX25519FromMnemonic(phrase)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte("browser interop "), 9000) // 144000 bytes: 3 frames

	random := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	hkdf32 := func(ikm, salt []byte, info string) []byte {
		out := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	gcm := func(key []byte) cipher.AEAD {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// Recipient block: eph key, KEK = HKDF(shared, eph||R_pub, "mdstn-cipher/v2/wrap").
	cek := random(32)
	ephPriv := random(32)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	kek := hkdf32(shared, append(append([]byte{}, ephPub...), recipientPub...), "mdstn-cipher/v2/wrap")
	wrapNonce := random(12)
	wrapped := gcm(kek).Seal(nil, wrapNonce, cek, []byte("mdstn-cipher/v2/wrap-cek"))

	headerJSON, err := json.Marshal(map[string]any{
		"chunked":           true,
		"encrypted_at":      1793750400,
		"original_filename": "hello.txt",
		"recipients": []map[string]string{{
			"ephemeral_pub_key": base64.StdEncoding.EncodeToString(ephPub),
			"nonce":             base64.StdEncoding.EncodeToString(wrapNonce),
			"wrapped_cek":       base64.StdEncoding.EncodeToString(wrapped),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte("MDST"), 0x03, 0x02)
	header = binary.BigEndian.AppendUint16(header, uint16(len(headerJSON))) // #nosec G115 -- small test header
	header = append(header, headerJSON...)

	mac := hmac.New(sha256.New, hkdf32(cek, nil, "mdstn-cipher/v2/header-mac"))
	mac.Write(header)
	payload := gcm(hkdf32(cek, nil, "mdstn-cipher/v2/payload"))

	file := append(append([]byte{}, header...), mac.Sum(nil)...)
	base := random(12)
	file = append(file, base...)
	for i, off := uint64(0), 0; ; i++ {
		end := min(off+65536, len(plaintext))
		final := end == len(plaintext)
		nonce := append([]byte{}, base...)
		for j, b := range binary.BigEndian.AppendUint64(nil, i) {
			nonce[4+j] ^= b
		}
		aad := binary.BigEndian.AppendUint64(append([]byte{}, header...), i)
		if final {
			aad = append(aad, 1)
		} else {
			aad = append(aad, 0)
		}
		ct := payload.Seal(nil, nonce, plaintext[off:end], aad)
		file = binary.BigEndian.AppendUint32(file, uint32(len(ct))) // #nosec G115 -- ≤ 65552
		file = append(file, ct...)
		if final {
			break
		}
		off = end
	}
	file = append(file, 0, 0, 0, 0)

	repo := &oneKeyRepo{}
	uc := usecases.NewDecryptFile(repo, localcrypto.NewEngine(), localcrypto.NewArgon2idKEKProvider(), nil, localcrypto.NewFileEncoder(), nil, quiet{}, nil, nil)
	var out bytes.Buffer
	if _, err := uc.DecryptStream(context.Background(), bytes.NewReader(file), &out, &usecases.DecryptStreamRequest{RecoveryPassphrase: phrase}); err != nil {
		t.Fatalf("production decoder rejected the independent encoding: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatal("plaintext mismatch")
	}
}

type quiet struct{}

func (quiet) ReportProgress(string, int) {}
func (quiet) ReportError(error)          {}
func (quiet) ReportSuccess(string)       {}

// oneKeyRepo lists one local X25519 key; the recovery phrase gives its
// private key.
type oneKeyRepo struct{ usecases.KeyRepository }

func (oneKeyRepo) List(context.Context, usecases.KeyFilters) ([]*entities.IdentityKey, error) {
	return []*entities.IdentityKey{{ID: "local", Type: entities.KeyTypeX25519}}, nil
}

func (oneKeyRepo) Update(context.Context, *entities.IdentityKey) error { return nil }
