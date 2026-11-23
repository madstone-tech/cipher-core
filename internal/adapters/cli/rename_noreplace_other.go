//go:build !linux && !darwin

package cli

// renameNoReplace has no atomic implementation on this OS; the caller falls
// back to a hard link, then to a check and a rename.
func renameNoReplace(_, _ string) error { return errNoReplaceUnsupported }
