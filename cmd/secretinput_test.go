package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretFromFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{name: "no newline", content: "pw", want: "pw"},
		{name: "one LF removed", content: "pw\n", want: "pw"},
		{name: "one CRLF removed", content: "pw\r\n", want: "pw"},
		{name: "only one LF removed", content: "pw\n\n", want: "pw\n"},
		{name: "inner and leading space kept", content: " p w \n", want: " p w "},
		{name: "lone CR kept", content: "pw\r", want: "pw\r"},
		{name: "empty file", content: "", wantErr: true},
		{name: "only a newline", content: "\n", wantErr: true},
		{name: "only a CRLF", content: "\r\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := secretFromFile(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("secretFromFile = %q; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("secretFromFile: %v", err)
			}
			if got != tc.want {
				t.Fatalf("secretFromFile = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestSecretFromFileMissing(t *testing.T) {
	t.Parallel()
	if _, err := secretFromFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("secretFromFile on a missing path: want an error")
	}
}

// TestSecretFromFileStdin reads "-" from os.Stdin. It swaps the process-wide
// os.Stdin, so it does not run in parallel.
func TestSecretFromFileStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		if err := r.Close(); err != nil {
			t.Errorf("close pipe: %v", err)
		}
	})
	if _, err := w.WriteString("from-stdin\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := secretFromFile("-")
	if err != nil {
		t.Fatalf("secretFromFile(-): %v", err)
	}
	if got != "from-stdin" {
		t.Fatalf("secretFromFile(-) = %q; want %q", got, "from-stdin")
	}
}
