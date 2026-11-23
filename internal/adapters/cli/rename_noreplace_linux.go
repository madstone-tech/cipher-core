//go:build linux

package cli

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames from to to, and fails with an error that matches
// fs.ErrExist if to exists. It is one atomic step (renameat2 with
// RENAME_NOREPLACE, Linux 3.15+). errNoReplaceUnsupported means the kernel or
// the file system has no such rename; the caller then falls back.
func renameNoReplace(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return errNoReplaceUnsupported
	}
	return err
}
