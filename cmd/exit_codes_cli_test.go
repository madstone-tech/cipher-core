package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExitCodes runs one CLI case per exit code (contracts/cli.md §Exit codes).
func TestExitCodes(t *testing.T) {
	dir := t.TempDir()
	ownerDB := keyDB(t, dir, "owner.db")
	otherDB := keyDB(t, dir, "other.db")
	pub := createKey(t, dir, ownerDB, "owner-pass")
	createKey(t, dir, otherDB, "other-pass")
	ownerPass := writeTestFile(t, dir, "owner.pass", []byte("owner-pass\n"))
	otherPass := writeTestFile(t, dir, "other.pass", []byte("other-pass\n"))
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	randomFile := func(name string, n int) string {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return writeTestFile(t, dir, name, b)
	}
	small := randomFile("small.bin", 1<<10)
	large := randomFile("large.bin", 2<<20)

	// A recipient file, for the exit 0, 2, and 3 cases.
	recEnc := filepath.Join(dir, "small.rec.mdstn")
	mustCLI(t, dir, "--db", otherDB, "encrypt", small, "--recipient-key", pubB64, "-o", recEnc)

	t.Run("0 success", func(t *testing.T) {
		r := runCLI(t, dir, "--db", ownerDB, "decrypt", recEnc, "--key-passphrase-file", ownerPass, "-o", filepath.Join(dir, "ok.out"))
		if r.code != 0 {
			t.Fatalf("exit %d; want 0\nstderr: %s", r.code, r.stderr)
		}
	})

	t.Run("1 bad flag", func(t *testing.T) {
		r := runCLI(t, dir, "--db", ownerDB, "encrypt", small, "--no-such-flag")
		if r.code != 1 {
			t.Fatalf("exit %d; want 1\nstderr: %s", r.code, r.stderr)
		}
	})

	t.Run("2 tampered recipient file", func(t *testing.T) {
		data, err := os.ReadFile(recEnc)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 0x01 // last byte of the body tag
		tampered := writeTestFile(t, dir, "tampered.mdstn", data)
		out := filepath.Join(dir, "tampered.out")
		r := runCLI(t, dir, "--db", ownerDB, "decrypt", tampered, "--key-passphrase-file", ownerPass, "-o", out)
		if r.code != 2 {
			t.Fatalf("exit %d; want 2\nstderr: %s", r.code, r.stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("output exists after a tamper failure (stat: %v)", err)
		}
	})

	t.Run("3 file for another key", func(t *testing.T) {
		r := runCLI(t, dir, "--db", otherDB, "decrypt", recEnc, "--key-passphrase-file", otherPass, "-o", filepath.Join(dir, "other.out"))
		if r.code != 3 {
			t.Fatalf("exit %d; want 3\nstderr: %s", r.code, r.stderr)
		}
	})

	t.Run("4 wrong password, both framings", func(t *testing.T) {
		right := writeTestFile(t, dir, "right.pw", []byte("right-password\n"))
		wrong := writeTestFile(t, dir, "wrong.pw", []byte("wrong-password\n"))
		var messages []string
		for _, src := range []string{small, large} {
			enc := src + ".pw.mdstn"
			mustCLI(t, dir, "--db", ownerDB, "encrypt", src, "--password-file", right, "-o", enc)
			out := src + ".pw.out"
			r := runCLI(t, dir, "--db", ownerDB, "decrypt", enc, "--password-file", wrong, "-o", out)
			if r.code != 4 {
				t.Errorf("%s: exit %d; want 4\nstderr: %s", filepath.Base(src), r.code, r.stderr)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("%s: output exists after a wrong password (stat: %v)", filepath.Base(src), err)
			}
			messages = append(messages, errorLine(r.stderr))
		}
		if messages[0] != messages[1] {
			t.Errorf("wrong-password messages differ:\n1 KiB: %q\n2 MiB: %q", messages[0], messages[1])
		}
	})
}

// errorLine returns the "Error: ..." line that main prints.
func errorLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "Error: ") {
			return line
		}
	}
	return ""
}
