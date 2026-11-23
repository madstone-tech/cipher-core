package cipher_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestDefaultLoggerWritesStderr: a Client without Config.Logger logs to
// stderr and writes nothing to stdout (spec FR-013).
func TestDefaultLoggerWritesStderr(t *testing.T) {
	dir := t.TempDir()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	realStdout, realStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	restored := false
	restore := func() {
		if !restored {
			os.Stdout, os.Stderr = realStdout, realStderr
			restored = true
		}
	}
	defer restore()

	client, err := cipher.NewLocal(filepath.Join(dir, "cipher.db"))
	if err != nil {
		restore()
		t.Fatal(err)
	}
	_, createErr := client.CreateKey(context.Background(), "logtest", "a-strong-key-passphrase")
	closeErr := client.Close()
	restore()
	if createErr != nil {
		t.Fatal(createErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	for _, f := range []*os.File{stdout, stderr} {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	out, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("default logger wrote to stdout: %q", out)
	}
	logged, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "level=INFO") {
		t.Fatalf("default logger wrote no log line to stderr: %q", logged)
	}
}
