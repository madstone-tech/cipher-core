package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestPublishWithPlaceholder covers S-4: the last no-replace fallback
// refuses an existing name (leaving it unchanged) and publishes a free one.
func TestPublishWithPlaceholder(t *testing.T) {
	dir := t.TempDir()
	tmp, final := filepath.Join(dir, "tmp"), filepath.Join(dir, "final")
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishWithPlaceholder(tmp, final); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing target: err = %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(final); string(got) != "old" {
		t.Fatalf("existing target changed to %q", got)
	}

	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := publishWithPlaceholder(tmp, final); err != nil {
		t.Fatalf("free target: %v", err)
	}
	if got, _ := os.ReadFile(final); string(got) != "new" {
		t.Fatalf("target = %q, want the staged bytes", got)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staged file still exists (stat err = %v)", err)
	}
}
