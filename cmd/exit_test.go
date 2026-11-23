package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

func TestExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, 0},
		{"other error", errors.New("boom"), 1},
		{"invalid recipient key is a usage error", entities.ErrInvalidRecipientKey, 1},
		{"header auth failed", entities.ErrHeaderAuthFailed, 2},
		{"wrapped header auth failed", fmt.Errorf("decrypt: %w", entities.ErrHeaderAuthFailed), 2},
		{"chunk auth error", &entities.ChunkAuthError{Index: 7}, 2},
		{"wrapped chunk auth error", fmt.Errorf("stream: %w", &entities.ChunkAuthError{Index: 1}), 2},
		{"not a recipient", entities.ErrNotARecipient, 3},
		{"wrapped not a recipient", fmt.Errorf("x: %w", entities.ErrNotARecipient), 3},
		{"wrong password", entities.ErrWrongPassword, 4},
		{"wrong password wins over chunk 0", fmt.Errorf("%w: %w", entities.ErrWrongPassword, &entities.ChunkAuthError{Index: 0}), 4},
		{"recovery aborted", entities.ErrRecoveryAborted, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitCode(tc.err); got != tc.want {
				t.Fatalf("ExitCode(%v) = %d; want %d", tc.err, got, tc.want)
			}
		})
	}
}
