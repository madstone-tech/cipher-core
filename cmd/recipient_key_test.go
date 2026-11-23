package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRecipientKey(t *testing.T) {
	t.Parallel()

	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	dir := t.TempDir()
	writeFile := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	b64 := base64.StdEncoding.EncodeToString
	lowOrder := map[string][]byte{
		"zero point":          make([]byte, 32),
		"point one":           append([]byte{1}, make([]byte, 31)...),
		"order-8 point":       mustHex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		"other order-8 point": mustHex(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		"p-1 (order 2)":       mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}

	t.Run("inline base64", func(t *testing.T) {
		t.Parallel()
		got, err := parseRecipientKey(pubB64)
		if err != nil {
			t.Fatalf("parseRecipientKey: %v", err)
		}
		if !bytes.Equal(got, pub) {
			t.Fatal("parsed key differs from the input")
		}
	})

	t.Run("path with trimmed base64", func(t *testing.T) {
		t.Parallel()
		p := writeFile("pub.b64", "  "+pubB64+"\n\n")
		got, err := parseRecipientKey(p)
		if err != nil {
			t.Fatalf("parseRecipientKey(path): %v", err)
		}
		if !bytes.Equal(got, pub) {
			t.Fatal("parsed key differs from the file content")
		}
	})

	invalid := []struct {
		name string
		v    string
	}{
		{"short base64 that is not a file", "AAAA"},
		{"33 bytes", b64(append(bytes.Clone(pub), 0))},
		{"31 bytes", b64(pub[:31])},
		{"empty", ""},
		{"path with wrong length", writeFile("short.b64", "AAAA\n")},
		{"path with garbage", writeFile("garbage.b64", "not base64 at all!\n")},
		{"raw-url base64 is not std base64", base64.RawURLEncoding.EncodeToString(pub)},
	}
	for name, k := range lowOrder {
		invalid = append(invalid, struct {
			name string
			v    string
		}{"low order " + name, b64(k)})
		invalid = append(invalid, struct {
			name string
			v    string
		}{"low order in file " + name, writeFile(hex.EncodeToString(k[:4])+".b64", b64(k)+"\n")})
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseRecipientKey(tc.v)
			if err == nil {
				t.Fatalf("parseRecipientKey(%q) = %x; want an error", tc.v, got)
			}
			if !errors.Is(err, entities.ErrInvalidRecipientKey) {
				t.Fatalf("parseRecipientKey(%q) error %v does not match ErrInvalidRecipientKey", tc.v, err)
			}
		})
	}
}
