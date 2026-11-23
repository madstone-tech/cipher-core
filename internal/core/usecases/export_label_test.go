package usecases

import (
	"context"
	"encoding/pem"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// TestPEMExportLabelSaysWrapped covers T-8: the PEM export holds the wrapped
// private key, and its label must not claim a raw private key.
func TestPEMExportLabelSaysWrapped(t *testing.T) {
	key := &entities.IdentityKey{ID: "k1", Type: entities.KeyTypeX25519, WrappedPrivateKey: []byte("wrapped-bytes")}
	uc := NewManageKeys(&fakeKeyRepo{keys: []*entities.IdentityKey{key}}, &fakeLogger{})
	resp, err := uc.ExportKey(context.Background(), &ExportKeyRequest{ID: "k1", Format: "pem"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(resp.Data)
	if block == nil || block.Type != "MDSTN WRAPPED X25519 PRIVATE KEY" {
		t.Fatalf("PEM block = %+v, want the wrapped-key label", block)
	}
}
