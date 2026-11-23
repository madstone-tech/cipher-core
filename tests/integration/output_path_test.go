package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// TestDefaultOutputPathStaysInInputDir covers Q1 and R-1: without an output
// path, the plaintext goes next to the input file (not into the working
// directory), its name comes from the input file name (never from the
// header's original_filename), and it never replaces an existing file unless
// Overwrite.
func TestDefaultOutputPathStaysInInputDir(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()

	src, plain := env.writeRandom(t, "report.txt", 4096)
	encPath := env.encryptFile(ctx, t, src)

	inbox := filepath.Join(env.dir, "inbox")
	if err := os.Mkdir(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(inbox, "received.mdstn")
	if err := os.Rename(encPath, moved); err != nil {
		t.Fatal(err)
	}

	// Run from another working directory: the output must not land there.
	t.Chdir(t.TempDir())
	want := filepath.Join(inbox, "received") // not "report.txt" from the header

	resp, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: moved, Passphrase: stagedTestPassphrase})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if resp.OutputPath != want {
		t.Fatalf("OutputPath = %q, want %q", resp.OutputPath, want)
	}
	if got, err := os.ReadFile(want); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("output = %d bytes, err %v; want the plaintext", len(got), err)
	}
	if resp.OriginalFilename != "report.txt" {
		t.Fatalf("OriginalFilename = %q, want the header value for display", resp.OriginalFilename)
	}
	if _, err := os.Stat(filepath.Join(inbox, "report.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the header name was used as a path (stat err = %v)", err)
	}

	// The default path now exists: a second decryption must not replace it.
	if err := os.WriteFile(want, []byte("KEEP"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: moved, Passphrase: stagedTestPassphrase})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second decrypt: err = %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(want); string(got) != "KEEP" {
		t.Fatalf("existing file changed to %d bytes", len(got))
	}
	// The failed commit left no staged partial file in the inbox.
	assertNoOutput(t, filepath.Join(inbox, "absent"))

	// Overwrite allows it.
	if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: moved, Passphrase: stagedTestPassphrase, Overwrite: true}); err != nil {
		t.Fatalf("decrypt with Overwrite: %v", err)
	}
	if got, _ := os.ReadFile(want); !bytes.Equal(got, plain) {
		t.Fatal("Overwrite did not replace the file")
	}
}

// TestEncryptStreamRejectsUnsafeOriginalFilename: an SDK caller cannot store a
// name that would steer a decryptor's output path.
func TestEncryptStreamRejectsUnsafeOriginalFilename(t *testing.T) {
	env := newStagedEnv(t)
	var out bytes.Buffer
	_, err := env.encrypt.EncryptStream(context.Background(), bytes.NewReader([]byte("x")), &out, &usecases.EncryptStreamRequest{
		Passphrase: stagedTestPassphrase, OriginalFilename: "../victim/target.txt",
	})
	if !errors.Is(err, entities.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes written before the error", out.Len())
	}
}

// TestPasswordFileHasNoFingerprint covers Q2: no result value may be derived
// from the file password (its SHA-256 skips the Argon2id cost).
func TestPasswordFileHasNoFingerprint(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	sum := sha256.Sum256([]byte(stagedTestPassphrase))

	for name, size := range map[string]int{"single-frame": 1 << 10, "stream": 2 << 20} {
		src, _ := env.writeRandom(t, name+".bin", size)
		resp, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if resp.Fingerprint != "" {
			t.Errorf("%s: Fingerprint = %q, want empty (sha256(password) = %s)", name, resp.Fingerprint, hex.EncodeToString(sum[:]))
		}
	}
}

// TestDecryptNeverReplacesTheInput covers R-2: neither an explicit output path
// nor Overwrite may write the plaintext over its own ciphertext.
func TestDecryptNeverReplacesTheInput(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	src, _ := env.writeRandom(t, "self.txt", 2048)
	encPath := env.encryptFile(ctx, t, src)
	before, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	link := encPath + ".link"
	if err := os.Link(encPath, link); err != nil {
		t.Fatal(err)
	}

	for name, req := range map[string]*usecases.DecryptFileRequest{
		"-o input":              {FilePath: encPath, OutputPath: encPath, Passphrase: stagedTestPassphrase},
		"-o input, Overwrite":   {FilePath: encPath, OutputPath: encPath, Overwrite: true, Passphrase: stagedTestPassphrase},
		"-o hard link to input": {FilePath: encPath, OutputPath: link, Overwrite: true, Passphrase: stagedTestPassphrase},
	} {
		_, err := env.decrypt.Execute(ctx, req)
		if !errors.Is(err, entities.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
		if got, _ := os.ReadFile(encPath); !bytes.Equal(got, before) {
			t.Fatalf("%s: the input ciphertext changed", name)
		}
	}
}

// TestEncryptNeverReplacesSilently covers S-5 and S-7: the default
// <file>.mdstn never replaces an existing file unless Overwrite, no path may
// be the input, and a directory path fails before any work.
func TestEncryptNeverReplacesSilently(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	src, plain := env.writeRandom(t, "doc.txt", 2048)
	first := env.encryptFile(ctx, t, src)
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}

	_, err = env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
	if !errors.Is(err, entities.ErrAlreadyExists) || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second encrypt to the default path: err = %v, want ErrAlreadyExists", err)
	}
	if got, _ := os.ReadFile(first); !bytes.Equal(got, firstBytes) {
		t.Fatal("the first ciphertext was replaced")
	}
	if _, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase, Overwrite: true}); err != nil {
		t.Fatalf("Overwrite: %v", err)
	}

	for name, out := range map[string]string{"-o input": src, "-o directory": env.dir} {
		_, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, OutputPath: out, Passphrase: stagedTestPassphrase})
		if !errors.Is(err, entities.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	if got, _ := os.ReadFile(src); !bytes.Equal(got, plain) {
		t.Fatal("the plaintext input was replaced")
	}
}

// TestDecryptOutputDirectoryFailsFirst covers S-7 for decrypt.
func TestDecryptOutputDirectoryFailsFirst(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	src, _ := env.writeRandom(t, "d.txt", 1024)
	enc := env.encryptFile(ctx, t, src)
	_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: enc, OutputPath: env.dir, Passphrase: stagedTestPassphrase})
	if !errors.Is(err, entities.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput for a directory output path", err)
	}
}

// TestOutputNeverReplacesKeyDatabase: no output path, explicit or derived,
// with or without Overwrite, may replace the key database or its side files.
func TestOutputNeverReplacesKeyDatabase(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	db := filepath.Join(env.dir, "test.db") // the store that newStagedEnv opened
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}

	src, _ := env.writeRandom(t, "x.txt", 1024)
	enc := env.encryptFile(ctx, t, src)
	env.encrypt.ProtectKeyStore(db)
	env.decrypt.ProtectKeyStore(db)
	// A ciphertext named after the database: its derived output is the DB.
	named := db + ".mdstn"
	if err := os.Rename(enc, named); err != nil {
		t.Fatal(err)
	}

	cases := map[string]error{}
	_, cases["decrypt -o db"] = env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: named, OutputPath: db, Passphrase: stagedTestPassphrase})
	_, cases["decrypt derived = db, Overwrite"] = env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: named, Overwrite: true, Passphrase: stagedTestPassphrase})
	_, cases["encrypt -o db"] = env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, OutputPath: db, Passphrase: stagedTestPassphrase})
	for name, err := range cases {
		if !errors.Is(err, entities.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the key database was replaced")
	}
}

// TestOutputNeverCreatesKeyStoreSideFiles covers T-1 and T-2: no output may
// CREATE a SQLite side file of the key database (a "<db>-journal" that does
// not exist yet is played back into the database at the next open), in any
// case spelling, also when the database is given as a DSN with "file:" and a
// "?_pragma" query, and also through a derived default path.
func TestOutputNeverCreatesKeyStoreSideFiles(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	db := filepath.Join(env.dir, "test.db")
	src, _ := env.writeRandom(t, "j.txt", 512)
	enc := env.encryptFile(ctx, t, src)
	env.encrypt.ProtectKeyStore("file:" + db + "?_pragma=busy_timeout(1)")
	env.decrypt.ProtectKeyStore("file:" + db + "?_pragma=busy_timeout(1)")

	for _, name := range []string{"test.db", "test.db-journal", "test.db-wal", "test.db-shm", "test.db-mj1A2B3C", "TEST.DB-JOURNAL", "Test.db"} {
		out := filepath.Join(env.dir, name)
		if _, err := os.Stat(out); err == nil && name != "test.db" && !strings.EqualFold(name, "test.db") {
			t.Fatalf("%s exists before the test", name)
		}
		_, derr := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: enc, OutputPath: out, Overwrite: true, Passphrase: stagedTestPassphrase})
		_, eerr := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, OutputPath: out, Overwrite: true, Passphrase: stagedTestPassphrase})
		for op, err := range map[string]error{"decrypt": derr, "encrypt": eerr} {
			if !errors.Is(err, entities.ErrInvalidInput) {
				t.Errorf("%s -o %s: err = %v, want ErrInvalidInput", op, name, err)
			}
		}
		if name != "test.db" && !strings.EqualFold(name, "test.db") {
			if _, err := os.Stat(out); err == nil {
				t.Errorf("%s was created", name)
			}
		}
	}

	// Derived path, no options: a ciphertext saved as "<db>-journal.mdstn".
	derived := db + "-journal.mdstn"
	if err := os.Rename(enc, derived); err != nil {
		t.Fatal(err)
	}
	if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: derived, Passphrase: stagedTestPassphrase}); !errors.Is(err, entities.ErrInvalidInput) {
		t.Fatalf("decrypt of <db>-journal.mdstn without -o: err = %v, want ErrInvalidInput", err)
	}
	if _, err := os.Stat(db + "-journal"); err == nil {
		t.Fatal("the derived path created <db>-journal")
	}

	// Any other name in the database folder is refused too (U-3: the file
	// system can fold names that a name rule does not), but a subfolder is
	// a different folder.
	if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: derived, OutputPath: filepath.Join(env.dir, "\u212a.db-journal"), Passphrase: stagedTestPassphrase}); !errors.Is(err, entities.ErrInvalidInput) {
		t.Fatalf("KELVIN SIGN name next to the database: err = %v, want ErrInvalidInput", err)
	}
	sub := filepath.Join(env.dir, "out")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: derived, OutputPath: filepath.Join(sub, "test.db-journal"), Passphrase: stagedTestPassphrase}); err != nil {
		t.Fatalf("a subfolder of the database folder: %v", err)
	}
}

// TestOutputGuardFollowsDatabaseLinks covers U-1 and U-4: SQLite keeps the
// journal next to the file it opened. With a symlinked database, that is the
// folder of the real file. With a hard link, the user can open the other
// name later. Outputs into those folders are refused.
func TestOutputGuardFollowsDatabaseLinks(t *testing.T) {
	env := newStagedEnv(t)
	ctx := context.Background()
	real := filepath.Join(env.dir, "test.db")
	src, _ := env.writeRandom(t, "l.txt", 256)
	enc := env.encryptFile(ctx, t, src)

	other := t.TempDir()
	link := filepath.Join(other, "link.db")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	hardDir := t.TempDir()
	if err := os.Link(real, filepath.Join(hardDir, "k2.db")); err != nil {
		t.Fatal(err)
	}
	env.decrypt.ProtectKeyStore(link)

	for name, out := range map[string]string{
		"real folder of a symlinked database": filepath.Join(env.dir, "test.db-journal"),
		"folder of the symlink":               filepath.Join(other, "link.db-journal"),
		"folder of a hard link":               filepath.Join(hardDir, "k2.db-journal"),
	} {
		_, err := env.decrypt.Execute(ctx, &usecases.DecryptFileRequest{FilePath: enc, OutputPath: out, Passphrase: stagedTestPassphrase})
		if !errors.Is(err, entities.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: %s was created", name, out)
		}
	}
}

// TestCancelledBeforePublishLeavesNoFile covers T-6: a command that is
// cancelled (SIGINT/SIGTERM) before the publish step publishes nothing, also
// for a small single-frame file.
func TestCancelledBeforePublishLeavesNoFile(t *testing.T) {
	env := newStagedEnv(t)
	src, _ := env.writeRandom(t, "small.txt", 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := env.encrypt.Execute(ctx, &usecases.EncryptFileRequest{FilePath: src, Passphrase: stagedTestPassphrase})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	assertNoOutput(t, src+".mdstn")
}
