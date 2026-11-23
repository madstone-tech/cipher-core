package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBackupDefaultPathIsOutsideWorkingDir covers W1: without -o, the backup
// (wrapped private keys and salts) goes to ~/.mdstn/backups/ with mode 0600,
// not into the working directory.
func TestBackupDefaultPathIsOutsideWorkingDir(t *testing.T) {
	home := t.TempDir() // runCLI uses dir as both HOME and working directory
	db := filepath.Join(home, "c.db")
	createKey(t, home, db, "backup-pass")

	// A looser existing directory mode is tightened.
	if err := os.MkdirAll(filepath.Join(home, ".mdstn", "backups"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, ".mdstn", "backups"), 0o755); err != nil {
		t.Fatal(err)
	}

	mustCLI(t, home, "--db", db, "backup")

	if m, _ := filepath.Glob(filepath.Join(home, "cipher-backup-*.json")); len(m) != 0 {
		t.Fatalf("backup written to the working directory: %v", m)
	}
	found, err := filepath.Glob(filepath.Join(home, ".mdstn", "backups", "cipher-backup-"+time.Now().Format("20060102")+"-*.json"))
	if err != nil || len(found) != 1 {
		t.Fatalf("backups in ~/.mdstn/backups = %v (err %v), want 1 with date and time", found, err)
	}
	info, err := os.Stat(found[0])
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("backup mode = %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Join(home, ".mdstn", "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("backup directory mode = %o, want 700", mode)
	}
}

// TestBackupNeverReplaces covers S-6: a backup never replaces an existing
// file, with or without -o.
func TestBackupNeverReplaces(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, "c.db")
	createKey(t, home, db, "backup-pass")
	out := filepath.Join(home, "b.json")
	if err := os.WriteFile(out, []byte("EARLIER BACKUP"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, home, "--db", db, "backup", "-o", out)
	if r.code == 0 {
		t.Fatalf("backup -o onto an existing file succeeded:\n%s", r.stdout)
	}
	if got, _ := os.ReadFile(out); string(got) != "EARLIER BACKUP" {
		t.Fatal("the earlier backup was replaced")
	}
}

// TestBackupTwiceInOneSecond covers T-10: a second default backup in the same
// second gets a "-2" name; nothing is replaced and the command succeeds.
func TestBackupTwiceInOneSecond(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, "c.db")
	createKey(t, home, db, "backup-pass")
	mustCLI(t, home, "--db", db, "backup")
	mustCLI(t, home, "--db", db, "backup")
	found, err := filepath.Glob(filepath.Join(home, ".mdstn", "backups", "cipher-backup-*.json"))
	if err != nil || len(found) != 2 {
		t.Fatalf("backups = %v (err %v), want 2", found, err)
	}
}

// TestBackupRefusesKeyStoreFiles: backup -o never creates a key database side
// file (T-1 for backup).
func TestBackupRefusesKeyStoreFiles(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, "c.db")
	createKey(t, home, db, "backup-pass")
	if r := runCLI(t, home, "--db", db, "backup", "-o", db+"-journal"); r.code == 0 {
		t.Fatal("backup -o <db>-journal succeeded")
	}
	if _, err := os.Stat(db + "-journal"); err == nil {
		t.Fatal("<db>-journal was created")
	}
}
