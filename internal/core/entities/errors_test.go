package entities

import (
	"errors"
	"fmt"
	"testing"
)

func TestChunkAuthErrorClass(t *testing.T) {
	wrapped := fmt.Errorf("streaming decryption failed: %w", &ChunkAuthError{Index: 7})

	if !errors.Is(wrapped, ErrHeaderAuthFailed) {
		t.Fatal("a chunk failure must match ErrHeaderAuthFailed (exit 2)")
	}
	if errors.Is(wrapped, ErrWrongPassword) || errors.Is(wrapped, ErrNotARecipient) {
		t.Fatal("a chunk failure must not match another error class")
	}

	var ce *ChunkAuthError
	if !errors.As(wrapped, &ce) || ce.Index != 7 {
		t.Fatalf("errors.As must recover the chunk index, got %+v", ce)
	}
}
