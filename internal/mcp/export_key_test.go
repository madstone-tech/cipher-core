package mcp

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
)

// TestExportKeyWritesNoFile covers S-1: export_key returns the public export
// in the result and writes no file, even when the caller passes an "output"
// path (the key database in this test).
func TestExportKeyWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keys.db")
	s, err := NewServer(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := crypto.NewEngine().GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	imported, err := s.CallTool(ctx, "import_key", map[string]interface{}{"public_key": base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("import_key: %v", err)
	}
	keyID := imported.(map[string]interface{})["key_id"].(string)

	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.CallTool(ctx, "export_key", map[string]interface{}{"key_id": keyID, "output": dbPath})
	if err != nil {
		t.Fatalf("export_key: %v", err)
	}
	got := out.(map[string]interface{})
	if got["public_key"] != base64.StdEncoding.EncodeToString(pub) || got["id"] != keyID {
		t.Fatalf("export result = %v, want the key's id and base64 public key", got)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("export_key changed the file named by \"output\" (the key database)")
	}
	for _, tool := range s.ListTools() {
		if tool.Name == "export_key" {
			if _, ok := tool.InputSchema["properties"].(map[string]interface{})["output"]; ok {
				t.Fatal("export_key still advertises an output argument")
			}
		}
	}
}
