package entities

import (
	"strings"
	"testing"
)

func TestValidOriginalFilename(t *testing.T) {
	valid := []string{"", "report.pdf", "etcd-snapshot.db.zst", "naïve résumé.txt", ".hidden", "a..b", strings.Repeat("a", 255)}
	for _, name := range valid {
		if err := ValidOriginalFilename(name); err != nil {
			t.Errorf("ValidOriginalFilename(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		".", "..", "../x", "../../victim/target.txt", "/etc/passwd", "dir/file", `a\b`, `..\x`,
		"c:x", "C:", "file.txt:stream", "a\x00b", "a\nb", "a\tb", "a\x7fb", "\xff\xfe",
		strings.Repeat("a", 256),
		"invoice\u202efdp.exe", "a\u009bb", "a\u0085b", "x\u200fy", "x\u2066y", "x\u061cy",
		"zero\u200bwidth", "a\u200db", "a\u2060b", "\ufeffbom", "soft\u00adhyphen", "a\u2028b", "a\u2029b", "tag\U000e0041",
	}
	for _, name := range invalid {
		if err := ValidOriginalFilename(name); err == nil {
			t.Errorf("ValidOriginalFilename(%q) = nil, want an error", name)
		}
	}
}
