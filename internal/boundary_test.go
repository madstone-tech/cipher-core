package boundary_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMirrorBoundary: the core module must import NOTHING from the app-side
// delivery tree (server/api/web/entitlement and the server-side adapters), and
// its go.mod must not carry server-only deps.
func TestMirrorBoundary(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	forbidden := []string{
		"github.com/madstone-tech/cipher-core/internal/entitlement", // the split type's old home
		"github.com/madstone-tech/cipher-core/internal/adapters/auth",
		"github.com/madstone-tech/cipher-core/internal/adapters/server",
		"github.com/madstone-tech/cipher-core/internal/adapters/api",
		"github.com/madstone-tech/cipher-core/internal/adapters/web",
		"github.com/madstone-tech/cipher-core/internal/adapters/webauthn",
		"github.com/madstone-tech/cipher-core/internal/adapters/webhook",
		"github.com/madstone-tech/cipher-core/internal/adapters/telemetry",
		"github.com/madstone-tech/cipher-core/internal/adapters/config",
		"github.com/madstone-tech/cipher-core/internal/adapters/postgres",
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "boundary_test.go") {
			return nil // the gate's own forbidden list contains the patterns
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		src := string(raw)
		for _, bad := range forbidden {
			if strings.Contains(src, `"`+bad+`"`) {
				t.Errorf("%s: forbidden import %q (core must not import the app-side delivery tree)", rel, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// go.mod must not carry server-only deps.
	modRaw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(modRaw), "\n") {
		l := strings.TrimSpace(line)
		for _, dep := range []string{"go-chi", "a-h/templ", "go.opentelemetry.io", "go-webauthn"} {
			if strings.HasPrefix(l, `"`) {
				continue
			}
			if strings.Contains(l, dep) && (strings.Contains(l, "github.com/") || strings.Contains(l, "go.opentelemetry.io") || strings.Contains(l, "modernc")) {
				t.Errorf("go.mod carries server-only dependency: %s", l)
			}
		}
	}
}
