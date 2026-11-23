package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// TestStagedWriteLongName covers R-4: the staged temp name has a fixed length,
// so an output name of the maximum length (255 bytes) can be published.
func TestStagedWriteLongName(t *testing.T) {
	fh := NewFileHandler()
	for name, open := range map[string]func(string) (usecases.StagedWriter, error){
		"WriteStream":          fh.WriteStream,
		"WriteStreamExclusive": fh.WriteStreamExclusive,
	} {
		path := filepath.Join(t.TempDir(), strings.Repeat("n", 255))
		w, err := open(path)
		if err != nil {
			t.Fatalf("%s: open a staged writer for a 255-byte name: %v", name, err)
		}
		if _, err := w.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
		if err := w.Commit(); err != nil {
			t.Fatalf("%s: commit a 255-byte name: %v", name, err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != "data" {
			t.Fatalf("%s: read back %q, %v", name, got, err)
		}
	}
}
