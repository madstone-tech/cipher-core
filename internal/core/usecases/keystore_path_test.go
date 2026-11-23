package usecases

import "testing"

// TestKeyStorePath covers U-2: the guard must protect the file that the
// SQLite driver opens, so a "file:" URI is decoded the same way.
func TestKeyStorePath(t *testing.T) {
	for dsn, want := range map[string]string{
		"/a/cipher.db":                         "/a/cipher.db",
		"/a/cipher.db?_pragma=busy_timeout(1)": "/a/cipher.db",
		"file:/a/cipher%2Edb":                  "/a/cipher.db",
		"file:/a%2Fb/c.db?mode=rwc#x":          "/a/b/c.db",
		"file:///a/c.db":                       "/a/c.db",
		"file://localhost/a/c.db":              "/a/c.db",
		"/a/odd#name.db":                       "/a/odd#name.db",
		":memory:":                             "",
		"file::memory:?cache=shared":           "",
		"":                                     "",
	} {
		if got := KeyStorePath(dsn); got != want {
			t.Errorf("KeyStorePath(%q) = %q, want %q", dsn, got, want)
		}
	}
}
