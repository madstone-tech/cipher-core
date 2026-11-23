package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The CLI tests build the mdstn-cipher binary once per test process and run
// it as a subprocess, so they see the real exit codes and terminal behavior.

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		if err := os.RemoveAll(filepath.Dir(binPath)); err != nil {
			code = max(code, 1)
		}
	}
	os.Exit(code)
}

// cipherBinary returns the path of a freshly built mdstn-cipher binary.
func cipherBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary; skipped in -short mode")
	}
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mdstn-cipher-bin-")
		if err != nil {
			binErr = err
			return
		}
		name := "mdstn-cipher"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		p := filepath.Join(dir, name)
		out, err := exec.Command("go", "build", "-o", p, "./mdstn-cipher").CombinedOutput()
		if err != nil {
			binErr = errors.Join(err, errors.New(string(out)))
			return
		}
		binPath = p
	})
	if binErr != nil {
		t.Fatalf("build mdstn-cipher: %v", binErr)
	}
	return binPath
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// runCLI runs the binary in dir with stdin from /dev/null (no terminal),
// HOME set to dir, and MDSTN_KEY_PASSPHRASE unset.
func runCLI(t *testing.T, dir string, args ...string) cliResult {
	t.Helper()
	bin := cipherBinary(t)

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := devNull.Close(); err != nil {
			t.Errorf("close %s: %v", os.DevNull, err)
		}
	}()

	c := exec.Command(bin, args...)
	c.Dir = dir
	c.Stdin = devNull
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "MDSTN_KEY_PASSPHRASE=") {
			continue
		}
		env = append(env, kv)
	}
	c.Env = append(env, "HOME="+dir)

	err = c.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// mustCLI runs the binary and fails the test unless it exits 0.
func mustCLI(t *testing.T, dir string, args ...string) cliResult {
	t.Helper()
	r := runCLI(t, dir, args...)
	if r.code != 0 {
		t.Fatalf("%v: exit %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

type listedKey struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
}

// listKeys returns the keys of the store at db (`keys list --json`).
func listKeys(t *testing.T, dir, db string) []listedKey {
	t.Helper()
	r := mustCLI(t, dir, "--db", db, "keys", "list", "--json")
	var keys []listedKey
	if err := json.Unmarshal([]byte(r.stdout), &keys); err != nil {
		t.Fatalf("keys list --json: %v\n%s", err, r.stdout)
	}
	return keys
}

// createKey creates a key in the store at db with the key passphrase pass and
// returns its base64 public key.
func createKey(t *testing.T, dir, db, pass string) []byte {
	t.Helper()
	passFile := writeTestFile(t, dir, filepath.Base(db)+".pass", []byte(pass+"\n"))
	mustCLI(t, dir, "--db", db, "keys", "create", "--key-passphrase-file", passFile, "--yes", "--json")
	keys := listKeys(t, dir, db)
	if len(keys) != 1 {
		t.Fatalf("store %s holds %d keys after create; want 1", db, len(keys))
	}
	return keys[0].PublicKey
}

func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// keyDB returns a database path in its own folder under dir: no command may
// write into the folder of the key database.
func keyDB(t *testing.T, dir, name string) string {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(keys, name)
}
