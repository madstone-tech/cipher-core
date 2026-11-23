package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

type conformanceBundle struct {
	KeyID             string `json:"key_id"`
	PublicKey         string `json:"public_key"`
	WrappedPrivateKey string `json:"wrapped_private_key"`
	Argon2idSalt      string `json:"argon2id_salt"`
}

type conformanceVector struct {
	Name               string             `json:"name"`
	Method             int                `json:"method"`
	Expect             string             `json:"expect"`     // negative entries only
	MdstnFile          string             `json:"mdstn_file"` // filename relative to testdata/, not inline data
	PlaintextB64       string             `json:"plaintext_b64"`
	PlaintextRule      string             `json:"plaintext_rule"` // stream vectors: chunkedPlaintextRule
	PlaintextLen       int                `json:"plaintext_len"`
	PlaintextSHA256    string             `json:"plaintext_sha256"`
	FilePassword       string             `json:"file_password"`
	RecoveryPhrase     string             `json:"recovery_phrase"`
	RecipientPublicKey string             `json:"recipient_public_key"`
	Bundle             *conformanceBundle `json:"bundle"`
	KeyPassphrase      string             `json:"key_passphrase"`
	SharedKeyB64       string             `json:"shared_key_b64"`
}

type conformanceFile struct {
	Version  int                 `json:"version"`
	Vectors  []conformanceVector `json:"vectors"`
	Negative []conformanceVector `json:"negative"`
}

// coverage names a method and a framing.
type coverage struct {
	method  entities.EncryptionMethod
	chunked bool
}

func (c coverage) String() string {
	framing := "single frame"
	if c.chunked {
		framing = "stream"
	}
	return fmt.Sprintf("method %s, %s", c.method, framing)
}

// requiredNegative lists the negative fixtures the vectors MUST have, with
// their class (FR-007, FR-016).
var requiredNegative = map[string]string{
	"truncated-at-boundary":       expectTamper,
	"frame-after-final":           expectTamper,
	"frame-0-removed":             expectTamper,
	"empty-final-frame":           expectTamper,
	"two-cek":                     expectTamper,
	"bad-filename":                expectParse,
	"nan-in-header":               expectParse,
	"bidi-filename":               expectParse,
	"crlf-in-base64":              expectParse,
	"noncanonical-base64-padding": expectParse,
	"version-0x01":                expectParse,
	"version-0x02":                expectParse,
	"wrong-password":              expectWrongPassword,
	"not-a-recipient":             expectNotARecipient,
}

// TestVectorsConformance verifies Go against testdata/vectors.json; it reads
// and asserts, it never writes. Every vector decrypts to its plaintext, every
// method × framing has a verified vector, and every negative fixture fails
// with its expect class.
func TestVectorsConformance(t *testing.T) {
	f := loadConformanceVectors(t)
	engine := NewEngine()
	verified := map[coverage]int{}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			want := vectorPlaintext(t, v)
			container := readFixture(t, v)
			got, file, err := referenceDecrypt(engine, v, container)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if int(methodByte(file.Method)) != v.Method {
				t.Fatalf("header method %s, vector method %d", file.Method, v.Method)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(want))
			}
			verified[coverage{file.Method, file.Chunked}]++
		})
	}
	for _, m := range []entities.EncryptionMethod{entities.MethodX25519, entities.MethodPassphrase, entities.MethodSharedKey} {
		for _, chunked := range []bool{false, true} {
			if c := (coverage{m, chunked}); verified[c] == 0 {
				t.Errorf("no verified vector for %s", c)
			}
		}
	}

	seen := map[string]bool{}
	for _, v := range f.Negative {
		seen[v.Name] = true
		t.Run("negative/"+v.Name, func(t *testing.T) {
			if want, ok := requiredNegative[v.Name]; ok && want != v.Expect {
				t.Fatalf("vectors.json expect %q, the format requires %q", v.Expect, want)
			}
			_, _, err := referenceDecrypt(engine, v, readFixture(t, v))
			if err == nil {
				t.Fatalf("decrypted; want class %s", v.Expect)
			}
			if got := errorClass(err); got != v.Expect {
				t.Fatalf("class %s, want %s (err: %v)", got, v.Expect, err)
			}
		})
	}
	for name := range requiredNegative {
		if !seen[name] {
			t.Errorf("vectors.json has no negative fixture %q", name)
		}
	}
}

// errorClass maps a decrypt error to the expect class of vectors.json.
func errorClass(err error) string {
	switch {
	case errors.Is(err, entities.ErrHeaderAuthFailed):
		return expectTamper
	case errors.Is(err, entities.ErrNotARecipient):
		return expectNotARecipient
	case errors.Is(err, entities.ErrWrongPassword):
		return expectWrongPassword
	default:
		return expectParse
	}
}

// referenceDecrypt decrypts container with the key material of v in the
// order of docs/format-spec.md §Decryption: parse the header, read the
// header MAC, resolve the file key, verify the MAC, then decrypt the body
// with the payload key.
func referenceDecrypt(engine *Engine, v conformanceVector, container []byte) ([]byte, *entities.EncryptedFile, error) {
	r := bytes.NewReader(container)
	file, headerAAD, err := NewFileEncoder().DecodeHeader(r)
	if err != nil {
		return nil, nil, err
	}
	mac := make([]byte, entities.HeaderMACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, file, fmt.Errorf("read header MAC: %w", err)
	}
	fileKey, err := vectorFileKey(engine, v, file)
	if err != nil {
		return nil, file, err
	}
	ok, err := engine.VerifyHeaderMAC(fileKey, headerAAD, mac)
	if err != nil {
		return nil, file, err
	}
	if !ok {
		if file.Method == entities.MethodPassphrase {
			return nil, file, entities.ErrWrongPassword
		}
		return nil, file, fmt.Errorf("%w: header MAC", entities.ErrHeaderAuthFailed)
	}
	payloadKey, err := engine.DerivePayloadKey(fileKey)
	if err != nil {
		return nil, file, err
	}
	if file.Chunked {
		var out bytes.Buffer
		if err := engine.DecryptStream(context.Background(), r, &out, payloadKey, headerAAD); err != nil {
			return nil, file, err
		}
		return out.Bytes(), file, nil
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, file, err
	}
	if len(body) < 12+16 || len(body) > maxSingleFrameBodyLen {
		return nil, file, fmt.Errorf("%w: single-frame body of %d bytes", entities.ErrHeaderAuthFailed, len(body))
	}
	pt, err := engine.DecryptAES(body[12:], payloadKey, body[:12], headerAAD)
	if err != nil {
		return nil, file, fmt.Errorf("%w: %v", entities.ErrHeaderAuthFailed, err)
	}
	return pt, file, nil
}

// maxSingleFrameBodyLen is nonce(12) + (1 MiB − 1) + tag(16): the encoder uses
// the single frame below 1 MiB only.
const maxSingleFrameBodyLen = 12 + (1<<20 - 1) + 16

func readFixture(t *testing.T, v conformanceVector) []byte {
	t.Helper()
	container, err := os.ReadFile(filepath.Join(vectorsDir, v.MdstnFile))
	if err != nil {
		t.Fatalf("mdstn_file %q: %v", v.MdstnFile, err)
	}
	return container
}

// loadConformanceVectors reads testdata/vectors.json.
func loadConformanceVectors(t *testing.T) conformanceFile {
	t.Helper()
	path := filepath.Join(vectorsDir, "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("conformance vectors unreadable at %s: %v", path, err)
	}
	var f conformanceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("vectors.json is not valid JSON: %v", err)
	}
	if len(f.Vectors) == 0 || len(f.Negative) == 0 {
		t.Fatal("vectors.json has no vectors or no negative fixtures - the conformance bar is empty")
	}
	return f
}

// methodByte returns the container method byte of m.
func methodByte(m entities.EncryptionMethod) byte {
	switch m {
	case entities.MethodX25519:
		return 2
	case entities.MethodPassphrase:
		return 3
	case entities.MethodSharedKey:
		return 5
	default:
		return 0
	}
}

// vectorPlaintext returns the expected plaintext of v: inline base64, or the
// pattern plaintext checked against its length and SHA-256.
func vectorPlaintext(t *testing.T, v conformanceVector) []byte {
	t.Helper()
	if v.PlaintextB64 != "" {
		want, err := base64.StdEncoding.DecodeString(v.PlaintextB64)
		if err != nil {
			t.Fatalf("plaintext_b64: %v", err)
		}
		return want
	}
	if v.PlaintextRule != chunkedPlaintextRule {
		t.Fatalf("vector has no plaintext_b64 and an unknown plaintext_rule %q", v.PlaintextRule)
	}
	want := patternPlaintext(v.PlaintextLen)
	sum := sha256.Sum256(want)
	if hex.EncodeToString(sum[:]) != v.PlaintextSHA256 {
		t.Fatalf("plaintext_sha256 does not match %d bytes of %q", v.PlaintextLen, v.PlaintextRule)
	}
	return want
}

// vectorFileKey returns the file key of v: the Argon2id key (method 3), the
// policy key (method 5), or the CEK of the first block that opens (method 2).
func vectorFileKey(engine *Engine, v conformanceVector, file *entities.EncryptedFile) ([]byte, error) {
	switch file.Method {
	case entities.MethodPassphrase:
		return engine.DeriveFileKeyArgon2id(v.FilePassword, file.Salt)
	case entities.MethodSharedKey:
		key, err := base64.StdEncoding.DecodeString(v.SharedKeyB64)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("shared_key_b64: %d bytes, err %v", len(key), err)
		}
		return key, nil
	case entities.MethodX25519:
		priv, err := vectorX25519Key(engine, v)
		if err != nil {
			return nil, err
		}
		for i, b := range file.Recipients {
			d, err := b.Decode()
			if err != nil {
				return nil, fmt.Errorf("recipient block %d: %w", i, err)
			}
			if cek, err := engine.UnwrapCEK(d.WrappedCEK, d.EphemeralPubKey, d.Nonce, priv, []byte(entities.WrapCEKAAD)); err == nil {
				return cek, nil
			}
		}
		return nil, entities.ErrNotARecipient
	default:
		return nil, fmt.Errorf("unsupported method %s", file.Method)
	}
}

// vectorX25519Key returns the recipient private key of v, from the recovery
// phrase or from the backup bundle (Argon2id KEK, AAD "mdstn-wrapped-key:"+key_id),
// and checks the derived public key against the pinned one.
func vectorX25519Key(engine *Engine, v conformanceVector) ([]byte, error) {
	var pub, priv, wantPub []byte
	var err error
	switch {
	case v.RecoveryPhrase != "":
		if pub, priv, err = DeriveX25519FromMnemonic(v.RecoveryPhrase); err != nil {
			return nil, fmt.Errorf("DeriveX25519FromMnemonic: %w", err)
		}
		if wantPub, err = base64.StdEncoding.DecodeString(v.RecipientPublicKey); err != nil {
			return nil, fmt.Errorf("recipient_public_key: %w", err)
		}
	case v.Bundle != nil:
		salt, serr := base64.StdEncoding.DecodeString(v.Bundle.Argon2idSalt)
		wrapped, werr := base64.StdEncoding.DecodeString(v.Bundle.WrappedPrivateKey)
		if serr != nil || werr != nil {
			return nil, fmt.Errorf("bundle base64: salt %v, wrapped_private_key %v", serr, werr)
		}
		kek, err := engine.DeriveFileKeyArgon2id(v.KeyPassphrase, salt)
		if err != nil {
			return nil, fmt.Errorf("bundle KEK: %w", err)
		}
		if priv, err = NewArgon2idKEKProvider().UnwrapKey(wrapped, kek, v.Bundle.KeyID); err != nil {
			return nil, fmt.Errorf("bundle UnwrapKey: %w", err)
		}
		if pub, err = curve25519.X25519(priv, curve25519.Basepoint); err != nil {
			return nil, fmt.Errorf("bundle public key: %w", err)
		}
		if wantPub, err = base64.StdEncoding.DecodeString(v.Bundle.PublicKey); err != nil {
			return nil, fmt.Errorf("bundle public_key: %w", err)
		}
	default:
		return nil, errors.New("method-2 vector has neither recovery_phrase nor bundle")
	}
	// Pins the cipher-x25519-v1 derivation (and the bundle) forever.
	if !bytes.Equal(pub, wantPub) {
		return nil, errors.New("derived public key drifted from the pinned vector")
	}
	return priv, nil
}
