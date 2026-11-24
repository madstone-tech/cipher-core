package cmd

import (
	"errors"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// Exit codes of the mdstn-cipher binary (docs/format-spec.md §Governance item 5).
const (
	ExitOK            = 0
	ExitError         = 1
	ExitAuthFailed    = 2
	ExitNotARecipient = 3
	ExitWrongPassword = 4
	// Directory (CKD) response classes. 5: the server rejected a publish or
	// unpublish on binding-state grounds; the local key store is unchanged.
	// 6: a directory response failed its integrity check; nothing was cached.
	ExitConflict  = 5
	ExitIntegrity = 6
)

// ExitCode maps a command error to the process exit code. It is the only
// mapping; no command calls os.Exit itself.
//
// The most specific class wins: a wrong-password error that also wraps a
// chunk authentication failure exits 4, not 2.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, entities.ErrWrongPassword):
		return ExitWrongPassword
	case errors.Is(err, entities.ErrNotARecipient):
		return ExitNotARecipient
	case errors.Is(err, entities.ErrHeaderAuthFailed):
		return ExitAuthFailed
	case errors.Is(err, entities.ErrKDConflict):
		return ExitConflict
	case errors.Is(err, entities.ErrKDIntegrity):
		return ExitIntegrity
	case errors.Is(err, entities.ErrUnauthorized):
		// Key-directory server authorization rejections (401/403): the
		// container tamper class carries server auth failures too.
		return ExitAuthFailed
	default:
		return ExitError
	}
}
