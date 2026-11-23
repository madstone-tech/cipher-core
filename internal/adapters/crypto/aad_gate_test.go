package crypto

import (
	"os"
	"strings"
	"testing"
)

// TestNoNilAADProductionSites — a structural gate complementing the GCM
// behavioral tests: every GCM Seal/Open in the crypto adapter MUST
// pass a non-nil AAD argument. Production crypto without authentication is a
// silent regression; this asserts the source inventory directly.
func TestNoNilAADProductionSites(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for lineNo, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			isSeal := strings.Contains(trimmed, "gcm.Seal(") || strings.Contains(trimmed, "aesgcm.Seal(")
			isOpen := strings.Contains(trimmed, "gcm.Open(") || strings.Contains(trimmed, "aesgcm.Open(")
			if !isSeal && !isOpen {
				continue
			}
			// The AAD argument is the LAST argument of Seal/Open. Reject a
			// literal nil in that position.
			if strings.HasSuffix(trimmed, ", nil)") {
				t.Errorf("%s:%d: GCM call passes nil AAD (header binding violated): %s", name, lineNo+1, trimmed)
			}
		}
	}
}
