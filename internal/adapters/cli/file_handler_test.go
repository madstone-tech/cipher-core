package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteFileAtomicNoTmp verifies that WriteFile leaves no .tmp file behind
// after a successful write and that the final file contains the expected data.
func TestWriteFileAtomicNoTmp(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	finalPath := filepath.Join(dir, "output.mdstn")
	data := []byte("hello atomic world")

	if err := fh.WriteFile(finalPath, data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Final file must exist with correct content.
	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}

	// No staged partial file must remain.
	if left := stagedEntries(t, dir); len(left) != 0 {
		t.Errorf("partial files remain after WriteFile: %v", left)
	}
}

// stagedEntries returns the names of *.mdstn-partial files in dir.
func stagedEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".mdstn-partial") {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestStagedWriterCommitPublishes verifies that Commit publishes the bytes at
// the final path, removes the partial file, and uses mode 0600.
func TestStagedWriterCommitPublishes(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	finalPath := filepath.Join(dir, "output.mdstn")
	data := []byte("streamed data content")

	w, err := fh.WriteStream(finalPath)
	if err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Nothing at the final path before Commit; one partial file staged.
	if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("final path exists before Commit: %v", err)
	}
	staged := stagedEntries(t, dir)
	if len(staged) != 1 || !strings.HasPrefix(staged[0], ".mdstn-") {
		t.Fatalf("staged entries = %v, want one .mdstn-*.mdstn-partial", staged)
	}
	info, err := os.Stat(filepath.Join(dir, staged[0]))
	if err != nil {
		t.Fatalf("stat partial: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("partial mode = %o, want 600", perm)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile after Commit: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
	if left := stagedEntries(t, dir); len(left) != 0 {
		t.Errorf("partial files remain after Commit: %v", left)
	}
}

// TestStagedWriterAbortLeavesNoFile verifies that Abort removes the staged
// bytes and that nothing ever appears at the final path.
func TestStagedWriterAbortLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	finalPath := filepath.Join(dir, "output.mdstn")
	w, err := fh.WriteStream(finalPath)
	if err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if _, err := w.Write([]byte("partial plaintext")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
		t.Errorf("final path exists after Abort: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory not empty after Abort: %v", names)
	}
}

// TestStagedWriterStateTable checks every cell of the data-model.md
// §StagedWriter state table.
func TestStagedWriterStateTable(t *testing.T) {
	fh := NewFileHandler()

	t.Run("committed", func(t *testing.T) {
		dir := t.TempDir()
		finalPath := filepath.Join(dir, "c.bin")
		w, err := fh.WriteStream(finalPath)
		if err != nil {
			t.Fatalf("WriteStream: %v", err)
		}
		if _, err := w.Write([]byte("abc")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if _, err := w.Write([]byte("x")); err == nil {
			t.Error("Write after Commit: want error, got nil")
		}
		if err := w.Commit(); err != nil {
			t.Errorf("second Commit: want nil, got %v", err)
		}
		if err := w.Abort(); err != nil {
			t.Errorf("Abort after Commit: want nil, got %v", err)
		}
		got, err := os.ReadFile(finalPath)
		if err != nil {
			t.Fatalf("Abort after Commit removed the output: %v", err)
		}
		if string(got) != "abc" {
			t.Errorf("content = %q, want %q", got, "abc")
		}
	})

	t.Run("aborted", func(t *testing.T) {
		dir := t.TempDir()
		finalPath := filepath.Join(dir, "a.bin")
		w, err := fh.WriteStream(finalPath)
		if err != nil {
			t.Fatalf("WriteStream: %v", err)
		}
		if err := w.Abort(); err != nil {
			t.Fatalf("Abort: %v", err)
		}
		if _, err := w.Write([]byte("x")); err == nil {
			t.Error("Write after Abort: want error, got nil")
		}
		if err := w.Commit(); err == nil {
			t.Error("Commit after Abort: want error, got nil")
		}
		if err := w.Abort(); err != nil {
			t.Errorf("second Abort: want nil, got %v", err)
		}
		if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
			t.Errorf("final path exists after Commit-on-aborted: %v", err)
		}
	})
}

// TestStagingIgnoresPlantedSymlinks verifies that symlinks planted at the
// legacy predictable temp names (<out>.tmp, <out>.mdstn.tmp) are neither
// followed nor replaced by WriteStream or WriteFile.
func TestStagingIgnoresPlantedSymlinks(t *testing.T) {
	for _, suffix := range []string{".tmp", ".mdstn.tmp"} {
		for _, mode := range []string{"WriteStream", "WriteFile"} {
			t.Run(mode+suffix, func(t *testing.T) {
				dir := t.TempDir()
				fh := NewFileHandler()

				victim := filepath.Join(dir, "victim.txt")
				victimData := []byte("do not touch")
				if err := os.WriteFile(victim, victimData, 0o600); err != nil {
					t.Fatalf("create victim: %v", err)
				}
				finalPath := filepath.Join(dir, "out.mdstn")
				link := finalPath + suffix
				if err := os.Symlink(victim, link); err != nil {
					t.Fatalf("Symlink: %v", err)
				}

				payload := []byte("attacker-visible payload")
				switch mode {
				case "WriteStream":
					w, err := fh.WriteStream(finalPath)
					if err != nil {
						t.Fatalf("WriteStream: %v", err)
					}
					if _, err := w.Write(payload); err != nil {
						t.Fatalf("Write: %v", err)
					}
					if err := w.Commit(); err != nil {
						t.Fatalf("Commit: %v", err)
					}
				case "WriteFile":
					if err := fh.WriteFile(finalPath, payload); err != nil {
						t.Fatalf("WriteFile: %v", err)
					}
				}

				got, err := os.ReadFile(victim)
				if err != nil {
					t.Fatalf("read victim: %v", err)
				}
				if !bytes.Equal(got, victimData) {
					t.Errorf("victim modified through symlink: %q", got)
				}
				target, err := os.Readlink(link)
				if err != nil {
					t.Fatalf("planted symlink replaced or removed: %v", err)
				}
				if target != victim {
					t.Errorf("symlink target = %q, want %q", target, victim)
				}
				info, err := os.Lstat(finalPath)
				if err != nil {
					t.Fatalf("Lstat final: %v", err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					t.Error("final path is a symlink")
				}
				out, err := os.ReadFile(finalPath)
				if err != nil {
					t.Fatalf("read final: %v", err)
				}
				if !bytes.Equal(out, payload) {
					t.Errorf("final content = %q, want %q", out, payload)
				}
			})
		}
	}
}

// TestWriteStreamRemovesStalePartials verifies that the next write (WriteStream
// or WriteFile) prunes *.mdstn-partial files older than one hour in the output
// directory and keeps recent ones (they may belong to a concurrent writer).
func TestWriteStreamRemovesStalePartials(t *testing.T) {
	writes := map[string]func(fh *FileHandler, path string) error{
		"WriteStream": func(fh *FileHandler, path string) error {
			w, err := fh.WriteStream(path)
			if err != nil {
				return err
			}
			return w.Abort()
		},
		"WriteFile": func(fh *FileHandler, path string) error {
			return fh.WriteFile(path, []byte("payload"))
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			fh := NewFileHandler()

			stale := filepath.Join(dir, ".old.mdstn.123.mdstn-partial")
			recent := filepath.Join(dir, ".new.mdstn.456.mdstn-partial")
			for _, p := range []string{stale, recent} {
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatalf("create %s: %v", p, err)
				}
			}
			oldTime := time.Now().Add(-2 * time.Hour)
			if err := os.Chtimes(stale, oldTime, oldTime); err != nil {
				t.Fatalf("Chtimes: %v", err)
			}

			if err := write(fh, filepath.Join(dir, "out.mdstn")); err != nil {
				t.Fatalf("%s: %v", name, err)
			}

			if _, err := os.Stat(stale); !os.IsNotExist(err) {
				t.Errorf("stale partial still exists: %v", err)
			}
			if _, err := os.Stat(recent); err != nil {
				t.Errorf("recent partial removed: %v", err)
			}
		})
	}
}

// TestCleanupStaleTempFiles verifies that CleanupStaleTempFiles removes files
// older than one hour and leaves recent files untouched.
func TestCleanupStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	// Create an old .mdstn.tmp file (mtime = 2 hours ago).
	oldFile := filepath.Join(dir, "old.mdstn.tmp")
	if err := os.WriteFile(oldFile, []byte("stale"), 0o600); err != nil {
		t.Fatalf("create old file: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// Create a recent .mdstn.tmp file (mtime = now).
	recentFile := filepath.Join(dir, "recent.mdstn.tmp")
	if err := os.WriteFile(recentFile, []byte("fresh"), 0o600); err != nil {
		t.Fatalf("create recent file: %v", err)
	}

	// Create an old .mdstn-partial file (current staging suffix).
	oldPartial := filepath.Join(dir, ".old.mdstn.789.mdstn-partial")
	if err := os.WriteFile(oldPartial, []byte("stale"), 0o600); err != nil {
		t.Fatalf("create old partial: %v", err)
	}
	if err := os.Chtimes(oldPartial, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes partial: %v", err)
	}

	// Also create a non-.mdstn.tmp file that should always be untouched.
	otherFile := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(otherFile, []byte("keep"), 0o600); err != nil {
		t.Fatalf("create other file: %v", err)
	}
	if err := os.Chtimes(otherFile, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes other: %v", err)
	}

	if err := fh.CleanupStaleTempFiles(dir); err != nil {
		t.Fatalf("CleanupStaleTempFiles: %v", err)
	}

	// Old .mdstn.tmp must be gone.
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("old stale temp file still exists: %s", oldFile)
	}

	// Old .mdstn-partial must be gone.
	if _, err := os.Stat(oldPartial); !os.IsNotExist(err) {
		t.Errorf("old stale partial file still exists: %s", oldPartial)
	}

	// Recent .mdstn.tmp must still be present.
	if _, err := os.Stat(recentFile); err != nil {
		t.Errorf("recent temp file was incorrectly removed: %v", err)
	}

	// Non-.mdstn.tmp file must still be present.
	if _, err := os.Stat(otherFile); err != nil {
		t.Errorf("non-tmp file was incorrectly removed: %v", err)
	}
}

// TestReadFileRoundTrip exercises ReadFile to improve coverage.
func TestReadFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	path := filepath.Join(dir, "sample.txt")
	data := []byte("read me back")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := fh.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch")
	}
}

// TestReadStreamRoundTrip exercises ReadStream to improve coverage.
func TestReadStreamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	path := filepath.Join(dir, "stream.txt")
	data := []byte("stream content")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	rc, err := fh.ReadStream(path)
	if err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	defer rc.Close()

	buf := make([]byte, len(data))
	if _, err := rc.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("content mismatch")
	}
}

// TestCleanupStaleTempFilesNonexistentDir verifies that CleanupStaleTempFiles
// returns an error for a directory that does not exist.
func TestCleanupStaleTempFilesNonexistentDir(t *testing.T) {
	fh := NewFileHandler()
	err := fh.CleanupStaleTempFiles("/nonexistent/path/xyz")
	if err == nil {
		t.Error("expected error for nonexistent dir, got nil")
	}
}

// TestWriteStreamMultipleWrites exercises stagedWriter.Write across multiple calls.
func TestWriteStreamMultipleWrites(t *testing.T) {
	dir := t.TempDir()
	fh := NewFileHandler()

	finalPath := filepath.Join(dir, "multi.mdstn")
	w, err := fh.WriteStream(finalPath)
	if err != nil {
		t.Fatalf("WriteStream: %v", err)
	}

	chunks := [][]byte{[]byte("hello "), []byte("world"), []byte("!")}
	for _, c := range chunks {
		if _, err := w.Write(c); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := []byte("hello world!")
	if !bytes.Equal(got, want) {
		t.Errorf("content mismatch: got %q, want %q", got, want)
	}
}
