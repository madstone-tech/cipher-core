package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncryptChecksOutputBeforePrompt covers T-7: an existing default
// <file>.mdstn is reported before any password prompt or KDF. Without a
// terminal, the old order failed on the prompt ("no terminal") instead.
func TestEncryptChecksOutputBeforePrompt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.mdstn"), []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, dir, "--db", keyDB(t, dir, "c.db"), "encrypt", "x")
	if r.code != 1 || !strings.Contains(r.stderr, "already exists") || strings.Contains(r.stderr, "no terminal") {
		t.Fatalf("exit %d, stderr %q; want an 'already exists' error before any prompt", r.code, r.stderr)
	}
}
