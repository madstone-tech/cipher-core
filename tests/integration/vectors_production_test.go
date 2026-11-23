package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// prodVector is the part of an internal/testdata/vectors.json entry that the
// production decrypt path needs.
type prodVector struct {
	Name            string `json:"name"`
	Method          int    `json:"method"`
	File            string `json:"mdstn_file"`
	Expect          string `json:"expect"`
	FilePassword    string `json:"file_password"`
	RecoveryPhrase  string `json:"recovery_phrase"`
	KeyPassphrase   string `json:"key_passphrase"`
	PlaintextB64    string `json:"plaintext_b64"`
	PlaintextLen    int    `json:"plaintext_len"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	Bundle          *struct {
		KeyID             string `json:"key_id"`
		PublicKey         string `json:"public_key"`
		WrappedPrivateKey string `json:"wrapped_private_key"`
		Argon2idSalt      string `json:"argon2id_salt"`
	} `json:"bundle"`
}

const testdataDir = "../../internal/testdata"

func loadProdVectors(t *testing.T) (vectors, negative []prodVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdataDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors  []prodVector `json:"vectors"`
		Negative []prodVector `json:"negative"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 || len(doc.Negative) == 0 {
		t.Fatal("vectors.json has no vectors or no negative fixtures")
	}
	return doc.Vectors, doc.Negative
}

// prodDecrypt runs the fixture of v through the production
// DecryptFile.DecryptStream with a fresh key store (holding the bundle key
// when v has one) and the key material of v.
func prodDecrypt(t *testing.T, v prodVector) ([]byte, error) {
	t.Helper()
	ctx := context.Background()
	keyRepo, err := sqlite.NewIdentityKeyRepository(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keyRepo.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	engine := crypto.NewEngine()
	recovery := v.RecoveryPhrase
	if v.Bundle != nil {
		pub := mustB64(t, v.Bundle.PublicKey)
		key := &entities.IdentityKey{
			ID: v.Bundle.KeyID, Type: entities.KeyTypeX25519, Fingerprint: engine.Hash(pub), PublicKey: pub,
			WrappedPrivateKey: mustB64(t, v.Bundle.WrappedPrivateKey), Argon2idSalt: mustB64(t, v.Bundle.Argon2idSalt),
			CreatedAt: time.Now(), StorageMode: entities.StorageModeStandard, StorageBackend: entities.StorageBackendSQLite,
		}
		if err := keyRepo.Create(ctx, key); err != nil {
			t.Fatalf("store bundle key: %v", err)
		}
		recovery = v.KeyPassphrase
	}
	sessions := crypto.NewInMemorySessionStore(ctx)
	t.Cleanup(sessions.Stop)
	uc := usecases.NewDecryptFile(keyRepo, engine, crypto.NewArgon2idKEKProvider(), sessions,
		crypto.NewFileEncoder(), cli.NewFileHandler(), &noopProgress{}, &noopPrompter{}, logging.NewSimpleLogger())

	data, err := os.ReadFile(filepath.Join(testdataDir, v.File))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err = uc.DecryptStream(ctx, bytes.NewReader(data), &out, &usecases.DecryptStreamRequest{
		Passphrase: v.FilePassword, RecoveryPassphrase: recovery,
	})
	return out.Bytes(), err
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectorsThroughProductionDecrypt covers Q7: every committed vector must
// decrypt to its plaintext through the production DecryptFile path, not only
// through the test-local reference decryptor in internal/adapters/crypto.
func TestVectorsThroughProductionDecrypt(t *testing.T) {
	vectors, _ := loadProdVectors(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := prodDecrypt(t, v)
			if v.Method == 5 {
				// DecryptFile rejects shared-key files: only the managing client
				// holds the policy key (docs/format-spec.md §Limitations).
				if err == nil {
					t.Fatal("DecryptFile decrypted a shared-key file")
				}
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if v.PlaintextB64 != "" || v.PlaintextLen == 0 && v.PlaintextSHA256 == "" {
				if want := mustB64(t, v.PlaintextB64); !bytes.Equal(got, want) {
					t.Fatalf("plaintext = %d bytes, want %d", len(got), len(want))
				}
				return
			}
			sum := sha256.Sum256(got)
			if len(got) != v.PlaintextLen || hex.EncodeToString(sum[:]) != v.PlaintextSHA256 {
				t.Fatalf("plaintext = %d bytes (sha256 %x), want %d bytes", len(got), sum, v.PlaintextLen)
			}
		})
	}
}

// TestNegativeFixturesThroughProductionDecrypt covers Q7: every negative
// fixture must fail with its expect class through the production path.
func TestNegativeFixturesThroughProductionDecrypt(t *testing.T) {
	_, negative := loadProdVectors(t)
	classes := map[string]error{
		"tamper":          entities.ErrHeaderAuthFailed,
		"not_a_recipient": entities.ErrNotARecipient,
		"wrong_password":  entities.ErrWrongPassword,
	}
	for _, v := range negative {
		t.Run(v.Name, func(t *testing.T) {
			_, err := prodDecrypt(t, v)
			if err == nil {
				t.Fatal("negative fixture decrypted")
			}
			if v.Expect == "parse" {
				for name, class := range classes {
					if errors.Is(err, class) {
						t.Fatalf("err = %v is class %s, want a parse error", err, name)
					}
				}
				return
			}
			class, ok := classes[v.Expect]
			if !ok {
				t.Fatalf("unknown expect class %q", v.Expect)
			}
			if !errors.Is(err, class) {
				t.Fatalf("err = %v, want class %s", err, v.Expect)
			}
		})
	}
}
