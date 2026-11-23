//go:build unix

package cli

import (
	"os"
	"syscall"
)

// linkCount returns the hard-link count of fi.
func linkCount(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true //nolint:unconvert // Nlink is uint16 on darwin, uint64 on linux
}
