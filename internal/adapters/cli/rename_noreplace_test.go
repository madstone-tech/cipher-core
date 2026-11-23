//go:build linux || darwin

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestRenameNoReplace covers R-9: on Linux and macOS, the no-replace publish
// is one atomic rename that refuses an existing target.
func TestRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	if err := os.WriteFile(from, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := renameNoReplace(from, to)
	if errors.Is(err, errNoReplaceUnsupported) {
		t.Skip("the test file system has no no-replace rename")
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("rename onto an existing file: err = %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(to); string(got) != "old" {
		t.Fatalf("existing target changed to %q", got)
	}

	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(from, to); err != nil {
		t.Fatalf("rename onto a free name: %v", err)
	}
	if got, _ := os.ReadFile(to); string(got) != "new" {
		t.Fatalf("target = %q, want the renamed file", got)
	}
	if _, err := os.Stat(from); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("source still exists after rename (stat err = %v)", err)
	}
}
