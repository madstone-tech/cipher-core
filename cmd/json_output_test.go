package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// keyJSONFields are the field names of one key in `keys create --json` and
// `keys list --json`: snake_case, no wrapped private key, no salt.
var keyJSONFields = []string{"alias", "created_at", "expires_at", "fingerprint", "id", "is_default", "public_key", "type"}

// requireFields fails unless obj has exactly the fields want.
func requireFields(t *testing.T, what string, obj map[string]any, want []string) {
	t.Helper()
	got := make([]string, 0, len(obj))
	for k := range obj {
		got = append(got, k)
	}
	sort.Strings(got)
	w := slices.Clone(want)
	sort.Strings(w)
	if !slices.Equal(got, w) {
		t.Fatalf("%s fields = %v; want %v", what, got, w)
	}
}

// unmarshalStdout fails unless stdout is exactly one JSON value.
func unmarshalStdout(t *testing.T, what string, r cliResult, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("%s: stdout is not one JSON value: %v\nstdout: %s\nstderr: %s", what, err, r.stdout, r.stderr)
	}
}

// TestJSONStdout runs each --json command and parses its stdout with
// json.Unmarshal (spec US3 scenarios 1, 3, 4).
func TestJSONStdout(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "cipher.db")
	keyPass := writeTestFile(t, dir, "key.pass", []byte("key-pass\n"))

	// keys create --json
	var created map[string]any
	unmarshalStdout(t, "keys create --json", mustCLI(t, dir, "--db", db, "keys", "create",
		"--key-passphrase-file", keyPass, "--yes", "--json"), &created)
	requireFields(t, "keys create --json", created,
		append(slices.Clone(keyJSONFields), "recovery_mnemonic", "recovery_mnemonic_warning"))
	mnemonic, ok := created["recovery_mnemonic"].(string)
	if !ok {
		t.Fatalf("recovery_mnemonic is %T; want string", created["recovery_mnemonic"])
	}
	if n := len(strings.Fields(mnemonic)); n != 24 {
		t.Fatalf("recovery_mnemonic has %d words; want 24", n)
	}
	if w := created["recovery_mnemonic_warning"]; w != recoveryMnemonicWarning {
		t.Fatalf("recovery_mnemonic_warning = %v; want %q", w, recoveryMnemonicWarning)
	}

	// keys list --json
	var listed []map[string]any
	unmarshalStdout(t, "keys list --json", mustCLI(t, dir, "--db", db, "keys", "list", "--json"), &listed)
	if len(listed) != 1 {
		t.Fatalf("keys list --json: %d keys; want 1", len(listed))
	}
	requireFields(t, "keys list --json", listed[0], keyJSONFields)
	if listed[0]["id"] != created["id"] || listed[0]["public_key"] != created["public_key"] {
		t.Fatalf("keys list --json key %v differs from created key %v", listed[0], created)
	}

	// encrypt --json (for self) and encrypt --json (file password)
	src := writeTestFile(t, dir, "in.txt", []byte("hello json"))
	var encSelf map[string]any
	unmarshalStdout(t, "encrypt --json (self)", mustCLI(t, dir, "--db", db, "encrypt", src,
		"--key-passphrase-file", keyPass, "-o", filepath.Join(dir, "self.mdstn"), "--json"), &encSelf)

	pwFile := writeTestFile(t, dir, "pw", []byte("file-pw\n"))
	enc := filepath.Join(dir, "pw.mdstn")
	var encPw map[string]any
	unmarshalStdout(t, "encrypt --json (password)", mustCLI(t, dir, "--db", db, "encrypt", src,
		"--password-file", pwFile, "-o", enc, "--json"), &encPw)
	if encPw["output_path"] != enc {
		t.Fatalf("encrypt --json output_path = %v; want %s", encPw["output_path"], enc)
	}

	// decrypt --json; a quote in the output path must stay valid JSON.
	out := filepath.Join(dir, `out "q".txt`)
	var dec map[string]any
	unmarshalStdout(t, "decrypt --json", mustCLI(t, dir, "--db", db, "decrypt", enc,
		"--password-file", pwFile, "-o", out, "--json"), &dec)
	if dec["output_path"] != out {
		t.Fatalf("decrypt --json output_path = %v; want %s", dec["output_path"], out)
	}

	// version --json
	var ver map[string]any
	unmarshalStdout(t, "version --json", mustCLI(t, dir, "version", "--json"), &ver)

	// lookup --json, answered from a seeded CKD cache (no network).
	seedCKDCache(t, db, "alice@example.com")
	var look map[string]any
	unmarshalStdout(t, "lookup --json", mustCLI(t, dir, "--db", db, "lookup", "alice@example.com", "--json"), &look)
	if look["email"] != "alice@example.com" {
		t.Fatalf("lookup --json email = %v", look["email"])
	}
}

// seedCKDCache stores a CKD cache entry for email in the store at db.
func seedCKDCache(t *testing.T, db, email string) {
	t.Helper()
	repo, err := sqlite.NewIdentityKeyRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := repo.Close(); err != nil {
			t.Errorf("close %s: %v", db, err)
		}
	}()
	pub := make([]byte, 32)
	pub[0] = 9
	sum := sha256.Sum256(pub)
	now := time.Now().Unix()
	if err := sqlite.NewCKDCacheRepository(repo.DB()).Set(context.Background(), &usecases.CKDCacheEntry{
		Email:       email,
		PublicKey:   pub,
		Fingerprint: hex.EncodeToString(sum[:]),
		FirstSeen:   now,
		LastSeen:    now,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestKeysCreateNoTTYNeedsYes: without a terminal and without --yes,
// `keys create` fails with a message that names --yes and creates no key
// (spec US3 scenario 2).
func TestKeysCreateNoTTYNeedsYes(t *testing.T) {
	for _, mode := range [][]string{nil, {"--json"}} {
		t.Run(strings.Join(append([]string{"keys create"}, mode...), " "), func(t *testing.T) {
			dir := t.TempDir()
			db := keyDB(t, dir, "cipher.db")
			keyPass := writeTestFile(t, dir, "key.pass", []byte("key-pass\n"))
			args := append([]string{"--db", db, "keys", "create", "--key-passphrase-file", keyPass}, mode...)
			r := runCLI(t, dir, args...)
			if r.code != ExitError {
				t.Fatalf("exit %d; want %d\nstdout: %s\nstderr: %s", r.code, ExitError, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, "--yes") {
				t.Fatalf("stderr does not name --yes: %s", r.stderr)
			}
			if keys := listKeys(t, dir, db); len(keys) != 0 {
				t.Fatalf("store holds %d keys after the failed create; want 0", len(keys))
			}
		})
	}
}

// TestEncryptEmptyRecipient: an empty recipient value is a usage error
// (spec US3 scenario 5): exit 1, a message that says the value is empty, and
// no output file.
func TestEncryptEmptyRecipient(t *testing.T) {
	dir := t.TempDir()
	db := keyDB(t, dir, "cipher.db")
	src := writeTestFile(t, dir, "in.txt", []byte("hello"))

	cases := []struct {
		name string
		args []string
	}{
		{"recipient empty", []string{"--recipient", ""}},
		{"recipient-key empty", []string{"--recipient-key", ""}},
		{"recipient empty comma item", []string{"--recipient", "some-key-id,"}},
		{"recipient blank comma item", []string{"--recipient", "some-key-id, ,other-key-id"}},
		{"recipient-key blank", []string{"--recipient-key", "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".mdstn")
			args := append([]string{"--db", db, "encrypt", src, "-o", out}, tc.args...)
			r := runCLI(t, dir, args...)
			if r.code != ExitError {
				t.Fatalf("exit %d; want %d\nstderr: %s", r.code, ExitError, r.stderr)
			}
			if !strings.Contains(r.stderr, "must not be empty") {
				t.Fatalf("stderr is not an empty-recipient usage error: %s", r.stderr)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("output %s exists after the usage error (stat err %v)", out, err)
			}
		})
	}
}
