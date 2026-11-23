package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	_ "modernc.org/sqlite"
)

func TestRecoveryKeyRepository_CreateAndGet(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&mode=memory")
	if err != nil {
		t.Fatalf("failed to open in-memory DB: %v", err)
	}
	defer db.Close()

	repo := NewRecoveryKeyRepository(db)
	ctx := context.Background()

	// Get on empty repo must return ErrNotFound.
	_, err = repo.Get(ctx)
	if !errors.Is(err, entities.ErrNotFound) {
		t.Fatalf("Get on empty repo: got %v, want ErrNotFound", err)
	}

	// Count on empty repo must be 0.
	n, err := repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Count = %d, want 0", n)
	}

	// Create a valid RecoveryKey.
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	rk := &entities.RecoveryKey{
		ID:        "testid1234567890",
		Salt:      salt,
		CreatedAt: time.Now().Truncate(time.Second),
	}
	if err := repo.Create(ctx, rk); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Count must now be 1.
	n, err = repo.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}

	// Get must return the stored key.
	got, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ID != rk.ID {
		t.Errorf("ID = %q, want %q", got.ID, rk.ID)
	}
	if len(got.Salt) != 16 {
		t.Errorf("Salt length = %d, want 16", len(got.Salt))
	}
	for i, b := range got.Salt {
		if b != salt[i] {
			t.Errorf("Salt[%d] = %d, want %d", i, b, salt[i])
			break
		}
	}
	if got.CreatedAt.Unix() != rk.CreatedAt.Unix() {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, rk.CreatedAt)
	}
}
