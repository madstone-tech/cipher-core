//go:build !unix

package cli

import "os"

// linkCount is unknown on this platform: DirHoldsLink then reads the folder.
func linkCount(os.FileInfo) (uint64, bool) { return 0, false }
