package sqlite

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDatabaseFileMode covers S-6: the key database holds wrapped private
// keys and salts, so it is mode 0600 whatever the umask, and a looser mode of
// an existing file is tightened on open.
func TestDatabaseFileMode(t *testing.T) {
	db := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(db, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(db, 0o644); err != nil {
		t.Fatal(err)
	}
	repo, err := NewIdentityKeyRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	info, err := os.Stat(db)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("database mode = %o, want 600", mode)
	}
}
