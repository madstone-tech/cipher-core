package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fingerprintKey carries the JSON list fields the reference-spelling tests
// need: id, fingerprint, alias.
type fingerprintKey struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Alias       string `json:"alias"`
}

func fingerprintList(t *testing.T, dir, db string) []fingerprintKey {
	t.Helper()
	r := mustCLI(t, dir, "--db", db, "keys", "list", "--json")
	var keys []fingerprintKey
	if err := json.Unmarshal([]byte(r.stdout), &keys); err != nil {
		t.Fatalf("keys list --json: %v\n%s", err, r.stdout)
	}
	return keys
}

// TestKeysAcceptFingerprintRefs: export, alias, and delete accept a full
// fingerprint (upper- or lowercase) as the key reference, not only the
// internal ID — encrypt's positionals already accepted fingerprints, so the
// mismatch tripped the 2026-11-24 QA smoke run.
func TestKeysAcceptFingerprintRefs(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "c.db")
	createKey(t, dir, db, "ref-pass")
	keys := fingerprintList(t, dir, db)
	if len(keys) != 1 {
		t.Fatalf("setup produced %d keys, want 1", len(keys))
	}
	key := keys[0]
	upper := strings.ToUpper(key.Fingerprint)

	// Export by full fingerprint (uppercase) matches export by ID byte-exactly.
	mustCLI(t, dir, "--db", db, "keys", "export", key.ID, "--output", filepath.Join(dir, "id.pem"))
	byFP := runCLI(t, dir, "--db", db, "keys", "export", upper, "--output", filepath.Join(dir, "fp.pem"))
	if byFP.code != 0 {
		t.Fatalf("export by uppercase fingerprint failed: %s", byFP.stderr)
	}
	idPEM, err := os.ReadFile(filepath.Join(dir, "id.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fpPEM, _ := os.ReadFile(filepath.Join(dir, "fp.pem"))
	if string(idPEM) != string(fpPEM) {
		t.Error("export by fingerprint differs from export by ID")
	}
	if !strings.Contains(string(idPEM), "BEGIN MDSTN WRAPPED X25519") {
		t.Error("export output is not a wrapped-key PEM")
	}

	// Alias by full fingerprint.
	mustCLI(t, dir, "--db", db, "keys", "alias", key.Fingerprint, "by-fp")
	if aliased := fingerprintList(t, dir, db)[0]; aliased.Alias != "by-fp" {
		t.Errorf("alias not set: %q", aliased.Alias)
	}

	// Delete by fingerprint (fresh second store so the confirmed key survives
	// and createKey's single-key assertion holds).
	db2 := keyDB(t, dir, "victim.db")
	createKey(t, dir, db2, "ref-pass")
	victim := fingerprintList(t, dir, db2)[0]
	if r := runCLI(t, dir, "--db", db2, "keys", "delete", victim.Fingerprint); r.code != 0 {
		t.Fatalf("delete by fingerprint failed: %s", r.stderr)
	}
	if left := fingerprintList(t, dir, db2); len(left) != 0 {
		t.Errorf("wrong key deleted; store holds %d keys", len(left))
	}

	// Unknown reference still fails, and leaves no output file.
	if r := runCLI(t, dir, "--db", db, "keys", "export", "ffffffff", "--output", filepath.Join(dir, "no.pem")); r.code == 0 {
		t.Fatal("export of an unknown reference succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "no.pem")); err == nil {
		t.Error("output file created for an unknown reference")
	}
}
