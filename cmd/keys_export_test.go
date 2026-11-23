package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestKeysExportGuards: keys export --output never replaces the key database
// or writes into a directory; an ordinary existing file is replaced (an
// explicit path is the user's choice).
func TestKeysExportGuards(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "c.db")
	createKey(t, dir, db, "export-pass")
	id := listKeys(t, dir, db)[0].ID
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}

	if r := runCLI(t, dir, "--db", db, "keys", "export", id, "--output", db); r.code == 0 {
		t.Fatalf("export onto the key database succeeded")
	}
	if after, _ := os.ReadFile(db); !bytes.Equal(before, after) {
		t.Fatal("the key database changed")
	}
	if len(listKeys(t, dir, db)) != 1 {
		t.Fatal("the key database lost its key")
	}

	if r := runCLI(t, dir, "--db", db, "keys", "export", id, "--output", dir); r.code == 0 {
		t.Fatal("export onto a directory succeeded")
	}

	out := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(out, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, dir, "--db", db, "keys", "export", id, "--output", out)
	if got, _ := os.ReadFile(out); string(got) == "OLD" || len(got) == 0 {
		t.Fatalf("explicit export path was not replaced: %q", got)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("export mode = %o, want 600", mode)
	}
}
