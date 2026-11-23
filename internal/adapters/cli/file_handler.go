package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// FileHandler implements the FileHandler interface
type FileHandler struct{}

// NewFileHandler creates a new file handler
func NewFileHandler() *FileHandler {
	return &FileHandler{}
}

// ReadFile reads a file from disk
func (fh *FileHandler) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// stagedSuffix is the suffix of every in-progress output file.
const stagedSuffix = ".mdstn-partial"

// legacyTempSuffix is the predictable temp suffix used before staged writes.
// Only CleanupStaleTempFiles still recognises it.
const legacyTempSuffix = ".mdstn.tmp"

// staleTempAge is the age after which a staged file is considered abandoned.
const staleTempAge = time.Hour

// WriteFile writes data to path through the same staging as WriteStream: the
// bytes go to a fresh O_EXCL temp file in path's directory, are fsynced, and
// are renamed onto path. On any failure nothing appears at path.
func (fh *FileHandler) WriteFile(path string, data []byte) error {
	w, err := fh.WriteStream(path)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return errors.Join(fmt.Errorf("failed to write temp file: %w", err), w.Abort())
	}
	return w.Commit()
}

// ReadStream opens a file for streaming reads
func (fh *FileHandler) ReadStream(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// WriteStream stages output for path in a fresh temp file
// "<dir>/.<base>.<random>.mdstn-partial" (mode 0600, created with O_EXCL, so a
// planted file or symlink is never followed). Nothing appears at path until
// Commit succeeds. Before staging, abandoned partial files older than one hour
// in the same directory are removed (best effort).
func (fh *FileHandler) WriteStream(path string) (usecases.StagedWriter, error) {
	return stage(path, false)
}

// SameFile reports whether a and b name the same existing file (os.SameFile,
// so hard links and symlinks to the same file match). A missing path is not
// the same file.
func (fh *FileHandler) SameFile(a, b string) (bool, error) {
	ia, err := os.Stat(a)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	ib, err := os.Stat(b)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return os.SameFile(ia, ib), nil
}

// ResolvePath returns path with every symlink resolved, or path itself when
// it does not exist.
func (fh *FileHandler) ResolvePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return path, nil
	}
	return resolved, err
}

// DirHoldsLink reports whether folder dir has an entry that is the same file
// as file (a hard link). A file with one link (where the platform reports the
// count) is skipped without reading dir. Only regular entries of the same
// size are compared by identity.
func (fh *FileHandler) DirHoldsLink(dir, file string) (bool, error) {
	fi, err := os.Stat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if n, ok := linkCount(fi); ok && n <= 1 {
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return false, err
		}
		if info.Size() == fi.Size() && os.SameFile(info, fi) {
			return true, nil
		}
	}
	return false, nil
}

// Exists reports whether anything (file, directory, link) exists at path.
func (fh *FileHandler) Exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// IsDir reports whether path is an existing directory (after links).
func (fh *FileHandler) IsDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// WriteStreamExclusive is WriteStream, but Commit never replaces an existing
// file: it publishes with a hard link, which fails atomically if path exists
// (fs.ErrExist). On a file system without hard links, Commit checks for path
// and then renames (not atomic against a concurrent writer).
func (fh *FileHandler) WriteStreamExclusive(path string) (usecases.StagedWriter, error) {
	return stage(path, true)
}

func stage(path string, exclusive bool) (usecases.StagedWriter, error) {
	dir := filepath.Dir(path)
	removeStalePartials(dir)

	// os.CreateTemp opens with O_RDWR|O_CREATE|O_EXCL and mode 0600.
	// The temp name has a fixed length (R-4): a name that is derived from the
	// output name could exceed the 255-byte name limit.
	f, err := os.CreateTemp(dir, ".mdstn-*"+stagedSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	return &stagedWriter{file: f, tmpPath: f.Name(), finalPath: path, exclusive: exclusive}, nil
}

// CleanupStaleTempFiles scans dir for staged *.mdstn-partial files (and the
// legacy *.mdstn.tmp files) and removes any that are older than one hour. Removal errors are logged at WARN but do not cause the
// function to return an error (best-effort cleanup). ReadDir errors are returned.
//
// Wired into cmd/root.go initConfig() so stale files left by crashed
// processes are pruned on every CLI startup.
func (fh *FileHandler) CleanupStaleTempFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if !isStaleCandidate(entry.Name()) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			slog.Warn("failed to stat temp file",
				"path", filepath.Join(dir, entry.Name()),
				"error", err,
			)
			continue
		}

		if time.Since(info.ModTime()) <= staleTempAge {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		if err := os.Remove(fullPath); err != nil {
			slog.Warn("failed to remove stale temp file",
				"path", fullPath,
				"error", err,
			)
		} else {
			slog.Info("removed stale temp file", "path", fullPath)
		}
	}

	return nil
}

// isStaleCandidate reports whether name is a staged or legacy temp file.
func isStaleCandidate(name string) bool {
	return strings.HasSuffix(name, stagedSuffix) || strings.HasSuffix(name, legacyTempSuffix)
}

// removeStalePartials removes *.mdstn-partial files in dir older than
// staleTempAge. Failures are logged at WARN and never block the write.
func removeStalePartials(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("failed to scan for stale partial files", "dir", dir, "error", err)
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), stagedSuffix) || !entry.Type().IsRegular() {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			slog.Warn("failed to stat partial file", "path", fullPath, "error", err)
			continue
		}
		if time.Since(info.ModTime()) <= staleTempAge {
			continue
		}
		if err := os.Remove(fullPath); err != nil {
			slog.Warn("failed to remove stale partial file", "path", fullPath, "error", err)
		}
	}
}

// stagedWriterState is the lifecycle state of a stagedWriter.
type stagedWriterState int

const (
	stateOpen stagedWriterState = iota
	stateCommitted
	stateAborted
)

// errStagedWriterClosed is returned by Write on a committed or aborted writer
// and by Commit on an aborted writer.
var errStagedWriterClosed = errors.New("staged writer is closed")

// stagedWriter implements usecases.StagedWriter over a temp file.
// State table (data-model.md §StagedWriter):
//   - open: Write appends; Commit = fsync+close+rename; Abort = close+remove.
//   - committed: Write errors; Commit/Abort are no-ops returning nil.
//   - aborted: Write/Commit error; Abort is a no-op returning nil.
type stagedWriter struct {
	file      *os.File
	tmpPath   string
	finalPath string
	exclusive bool
	state     stagedWriterState
}

// Write appends p to the temp file.
func (w *stagedWriter) Write(p []byte) (int, error) {
	if w.state != stateOpen {
		return 0, errStagedWriterClosed
	}
	return w.file.Write(p)
}

// Commit fsyncs and closes the temp file, then renames it onto the final path.
// On failure the temp file is removed and the writer becomes aborted.
func (w *stagedWriter) Commit() error {
	switch w.state {
	case stateCommitted:
		return nil
	case stateAborted:
		return errStagedWriterClosed
	}
	if err := w.file.Sync(); err != nil {
		return w.fail(fmt.Errorf("failed to sync temp file: %w", err), true)
	}
	if err := w.file.Close(); err != nil {
		return w.fail(fmt.Errorf("failed to close temp file: %w", err), false)
	}
	if w.exclusive {
		if err := publishExclusive(w.tmpPath, w.finalPath); err != nil {
			return w.fail(err, false)
		}
	} else if err := os.Rename(w.tmpPath, w.finalPath); err != nil {
		return w.fail(fmt.Errorf("failed to rename to final path: %w", err), false)
	}
	w.state = stateCommitted
	return nil
}

// errNoReplaceUnsupported reports that the OS or file system has no atomic
// no-replace rename.
var errNoReplaceUnsupported = errors.New("no-replace rename is not supported")

// publishExclusive moves tmp to final only if final does not exist, in one
// atomic step where possible:
//  1. a no-replace rename (Linux renameat2, macOS renamex_np);
//  2. else a hard link, which also fails if final exists; the temp file is
//     removed afterwards (if that fails, only a stale partial remains, which
//     removeStalePartials deletes later);
//  3. else (FAT, exFAT, some network file systems) an O_EXCL placeholder at
//     the final name, then a rename over it (publishWithPlaceholder).
func publishExclusive(tmp, final string) error {
	switch err := renameNoReplace(tmp, final); {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("output file %s already exists: %w", final, fs.ErrExist)
	case !errors.Is(err, errNoReplaceUnsupported):
		return fmt.Errorf("failed to rename to final path: %w", err)
	}
	err := os.Link(tmp, final)
	switch {
	case err == nil:
		if rmErr := os.Remove(tmp); rmErr != nil {
			slog.Warn("failed to remove staged file after publishing", "path", tmp, "error", rmErr)
		}
		return nil
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("output file %s already exists: %w", final, fs.ErrExist)
	}
	// No hard links on this file system (FAT, exFAT, some network file
	// systems): reserve the name, then rename over the reservation.
	return publishWithPlaceholder(tmp, final)
}

// publishWithPlaceholder reserves final with O_CREAT|O_EXCL, which fails
// atomically if final exists, and then renames tmp over that placeholder.
// Another process cannot create final in between: the name is taken. (It
// could remove and recreate it, but that needs the write access to the
// directory that also lets it change the output after the fact.)
func publishWithPlaceholder(tmp, final string) error {
	f, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("output file %s already exists: %w", final, fs.ErrExist)
	} else if err != nil {
		return fmt.Errorf("failed to reserve output path: %w", err)
	}
	if err := f.Close(); err != nil {
		return errors.Join(fmt.Errorf("failed to reserve output path: %w", err), os.Remove(final))
	}
	if err := os.Rename(tmp, final); err != nil {
		return errors.Join(fmt.Errorf("failed to rename to final path: %w", err), os.Remove(final))
	}
	return nil
}

// Abort closes and removes the temp file. It is idempotent.
func (w *stagedWriter) Abort() error {
	if w.state != stateOpen {
		return nil
	}
	w.state = stateAborted
	return errors.Join(w.file.Close(), removeIfExists(w.tmpPath))
}

// fail moves the writer to aborted after a Commit failure, joining cleanup
// errors onto cause.
func (w *stagedWriter) fail(cause error, closeFile bool) error {
	w.state = stateAborted
	var closeErr error
	if closeFile {
		closeErr = w.file.Close()
	}
	return errors.Join(cause, closeErr, removeIfExists(w.tmpPath))
}

// removeIfExists removes path, treating "does not exist" as success.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to remove temp file: %w", err)
	}
	return nil
}
