//go:build darwin

package cli

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames from to to, and fails with an error that matches
// fs.ErrExist if to exists. It is one atomic step (renamex_np with
// RENAME_EXCL, macOS 10.12+). errNoReplaceUnsupported means the file system
// has no such rename; the caller then falls back.
func renameNoReplace(from, to string) error {
	err := unix.RenamexNp(from, to, unix.RENAME_EXCL)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
		return errNoReplaceUnsupported
	}
	return err
}
