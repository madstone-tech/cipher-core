package cipher_test

import (
	"os"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// TestNewFailsWithoutHome covers T-3: with no home directory and no
// Config.DBPath, New fails instead of creating ./cipher.db in the working
// directory.
func TestNewFailsWithoutHome(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	t.Setenv("HOME", "")
	c, err := cipher.New(cipher.Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("New succeeded without a home directory")
	}
	if _, statErr := os.Stat("cipher.db"); statErr == nil {
		t.Fatal("New created ./cipher.db in the working directory")
	}
}
