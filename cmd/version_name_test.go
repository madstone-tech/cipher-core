package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// A consumer binary (cipher's cipher-app) renames the root command. Both
// `version` and `--version` must report that name, not "mdstn-cipher".
func TestVersionReportsRootCommandName(t *testing.T) {
	oldUse := rootCmd.Use
	rootCmd.Use = "cipher-app"
	t.Cleanup(func() { rootCmd.Use = oldUse })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	execErr := (&VersionCommand{}).Execute(false)
	os.Stdout = oldStdout
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if execErr != nil {
		t.Fatalf("version: %v", execErr)
	}
	if got := string(out); !strings.HasPrefix(got, "cipher-app "+version+" ") {
		t.Errorf("version output = %q, want prefix %q", got, "cipher-app "+version+" ")
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	t.Cleanup(func() { rootCmd.SetOut(nil) })
	rootCmd.SetArgs([]string{"--version"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	if got, want := buf.String(), "cipher-app "+version+"\n"; got != want {
		t.Errorf("--version output = %q, want %q", got, want)
	}
}
