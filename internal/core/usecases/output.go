package usecases

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// KeyStorePath returns the file path of a SQLite data source name, as the
// driver opens it: it drops a "file:" prefix, a "//" or "//localhost"
// authority, a "?query" (for example "?_pragma=busy_timeout(1)") and a
// "#fragment", and it decodes %XX escapes in a "file:" URI (U-2:
// "file:cipher%2Edb" opens "cipher.db"). An in-memory or empty DSN gives ""
// (no file to protect).
func KeyStorePath(dsn string) string {
	path, uri := strings.CutPrefix(dsn, "file:")
	if i := strings.IndexAny(path, "?#"); uri && i >= 0 {
		path = path[:i]
	} else if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if rest, ok := strings.CutPrefix(path, "//"); uri && ok {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			path = rest[i:]
		} else {
			path = ""
		}
	}
	if uri {
		if decoded, err := url.PathUnescape(path); err == nil {
			path = decoded
		}
	}
	if path == "" || path == ":memory:" {
		return ""
	}
	return path
}

// CheckOutputPath refuses, before any crypto work:
//   - an output that is the input file (in any spelling: links, case);
//   - ANY output in a folder of a key database (keyStores are SQLite DSNs):
//     the configured folder, the folder of the resolved file (the database
//     path can be a symlink: SQLite keeps its journal next to the real file,
//     U-1), and a folder that holds another hard link to the database (U-4).
//     SQLite plays a valid "<db>-journal" back into the database at the next
//     open, so a sender-chosen plaintext there rewrites the key store. The
//     rule is by folder, not by name: name matching would have to copy every
//     case and Unicode folding rule of the file system (U-3);
//   - an output that is the database itself through another name;
//   - an existing directory.
//
// inputPath may be "" (no input file, for example a key export).
func CheckOutputPath(fh FileHandler, inputPath, outputPath string, keyStores []string) error {
	if inputPath != "" {
		if same, err := fh.SameFile(inputPath, outputPath); err != nil {
			return fmt.Errorf("failed to check output path: %w", err)
		} else if same {
			return fmt.Errorf("%w: output path %s is the input file", entities.ErrInvalidInput, outputPath)
		}
	}
	outDir := filepath.Dir(outputPath)
	for _, dsn := range keyStores {
		db := KeyStorePath(dsn)
		if db == "" {
			continue
		}
		inDBDir, err := isKeyStoreDir(fh, db, outDir)
		if err != nil {
			return fmt.Errorf("failed to check output path: %w", err)
		}
		if inDBDir {
			return fmt.Errorf("%w: output path %s is in the folder of the key database %s: choose another folder", entities.ErrInvalidInput, outputPath, db)
		}
		if same, err := fh.SameFile(db, outputPath); err != nil {
			return fmt.Errorf("failed to check output path: %w", err)
		} else if same {
			return fmt.Errorf("%w: output path %s is the key database", entities.ErrInvalidInput, outputPath)
		}
	}
	if dir, err := fh.IsDir(outputPath); err != nil {
		return fmt.Errorf("failed to check output path: %w", err)
	} else if dir {
		return fmt.Errorf("%w: output path %s is a directory", entities.ErrInvalidInput, outputPath)
	}
	return nil
}

// isKeyStoreDir reports whether dir is a folder that SQLite can use for the
// files of database db: its configured folder, its resolved folder, or a
// folder that holds another hard link to it.
func isKeyStoreDir(fh FileHandler, db, dir string) (bool, error) {
	dbDirs := []string{filepath.Dir(db)}
	resolved, err := fh.ResolvePath(db)
	if err != nil {
		return false, err
	}
	if resolved != db {
		dbDirs = append(dbDirs, filepath.Dir(resolved))
	}
	for _, d := range dbDirs {
		same, err := fh.SameFile(d, dir)
		if err != nil {
			return false, err
		}
		// Compare the cleaned paths too: a folder that does not exist yet
		// cannot be compared by identity.
		if same || filepath.Clean(d) == filepath.Clean(dir) {
			return true, nil
		}
	}
	return fh.DirHoldsLink(dir, db)
}

// refuseExisting fails early when path exists (an exclusive default path):
// the caller learns it before any prompt or KDF. The publish step repeats the
// check atomically.
func refuseExisting(fh FileHandler, path string) error {
	exists, err := fh.Exists(path)
	if err != nil {
		return fmt.Errorf("failed to check output path: %w", err)
	}
	if exists {
		return fmt.Errorf("%w: output file %s already exists: %w", entities.ErrAlreadyExists, path, fs.ErrExist)
	}
	return nil
}

// openOutput stages output for path. An exclusive writer (a default path that
// the caller did not choose) never replaces an existing file.
func openOutput(fh FileHandler, path string, exclusive bool) (StagedWriter, error) {
	open := fh.WriteStream
	if exclusive {
		open = fh.WriteStreamExclusive
	}
	w, err := open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open output stream: %w", err)
	}
	return w, nil
}

// commitOutput publishes w, unless ctx is already cancelled (SIGINT or
// SIGTERM during the work): then it aborts and nothing is published (T-6).
// An existing file at an exclusive path gives an error that matches
// entities.ErrAlreadyExists and fs.ErrExist.
func commitOutput(ctx context.Context, w StagedWriter) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(err, w.Abort())
	}
	if err := w.Commit(); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %w", entities.ErrAlreadyExists, err)
		}
		return fmt.Errorf("failed to finalise output stream: %w", err)
	}
	return nil
}
