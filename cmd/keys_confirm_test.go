package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// fakeWords answers every confirmation prompt with word, or fails with err.
type fakeWords struct {
	word string
	err  error
}

func (f fakeWords) PromptString(string) (string, error) { return f.word, f.err }

// TestKeysCreateFailedConfirmationKeepsNoKey: a wrong or unreadable
// confirmation word deletes the new key, and the error says so.
func TestKeysCreateFailedConfirmationKeepsNoKey(t *testing.T) {
	cases := []struct {
		name  string
		words fakeWords
	}{
		{"mismatch", fakeWords{word: "not-a-bip39-word"}},
		{"read error", fakeWords{err: errors.New("EOF")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "cipher.db")
			c := NewKeysCommand(db, false, false)
			c.stdinIsTerminal = func() bool { return true }
			c.words = tc.words

			err := c.Create(context.Background(), "x25519", "", "", "", "key-pass", false)
			if err == nil {
				t.Fatal("Create succeeded with a failed confirmation")
			}
			if !strings.Contains(err.Error(), "NOT kept") || !strings.Contains(err.Error(), "run the command again") {
				t.Fatalf("error does not say the key was not kept: %v", err)
			}

			adapters, err := NewCommonAdapters(db)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := adapters.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()
			keys, err := adapters.KeyRepo.List(context.Background(), usecases.KeyFilters{})
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 0 {
				t.Fatalf("store holds %d keys after the failed confirmation; want 0", len(keys))
			}
		})
	}
}

type failingDeleter struct{ err error }

func (f failingDeleter) Delete(context.Context, string) error { return f.err }

// TestDiscardUnconfirmedKeyDeleteFails: when the delete fails, the error
// keeps both causes and names the key that may still exist.
func TestDiscardUnconfirmedKeyDeleteFails(t *testing.T) {
	cause := errors.New("word #3 did not match")
	delErr := errors.New("disk I/O error")
	err := discardUnconfirmedKey(context.Background(), failingDeleter{err: delErr}, "abc123", cause)
	if !errors.Is(err, cause) || !errors.Is(err, delErr) {
		t.Fatalf("error does not wrap both causes: %v", err)
	}
	if !strings.Contains(err.Error(), "abc123 may still exist") {
		t.Fatalf("error does not name the key that may still exist: %v", err)
	}
	if strings.Contains(err.Error(), "NOT kept") {
		t.Fatalf("error claims the key was not kept: %v", err)
	}
}
