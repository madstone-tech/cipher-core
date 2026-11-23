package usecases

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cryptoadapter "github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// TestEncryptRejectsNonCanonicalRecipientKey checks FR-004 (V2-2) at the
// usecase boundary that every path (raw key, local key, CKD, SDK, MCP) goes
// through: a recipient key with bit 255 set fails with ErrInvalidRecipientKey
// before any output, even next to a valid recipient.
func TestEncryptRejectsNonCanonicalRecipientKey(t *testing.T) {
	pub, _, err := cryptoadapter.NewEngine().GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bit255 := append([]byte{}, pub...)
	bit255[31] |= 0x80
	recipients := []Recipient{{PublicKey: pub, Fingerprint: "good"}, {PublicKey: bit255, Fingerprint: "bit255"}}

	in := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(in, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	fh := newFakeFileHandler()
	fh.files[in] = []byte("hello")
	uc := newTestEncryptFile(&fakeKeyRepo{}, fh)

	_, err = uc.Execute(context.Background(), &EncryptFileRequest{FilePath: in, Recipients: recipients})
	if !errors.Is(err, entities.ErrInvalidRecipientKey) {
		t.Fatalf("Execute: err = %v, want ErrInvalidRecipientKey", err)
	}
	if _, ok := fh.files[in+".mdstn"]; ok {
		t.Error("Execute wrote an output file")
	}

	var dst bytes.Buffer
	_, err = uc.EncryptStream(context.Background(), bytes.NewReader([]byte("hello")), &dst, &EncryptStreamRequest{Recipients: recipients})
	if !errors.Is(err, entities.ErrInvalidRecipientKey) {
		t.Fatalf("EncryptStream: err = %v, want ErrInvalidRecipientKey", err)
	}
	if dst.Len() != 0 {
		t.Errorf("EncryptStream wrote %d bytes", dst.Len())
	}
}
