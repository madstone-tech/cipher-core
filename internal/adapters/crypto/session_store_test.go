package crypto

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSessionStore_SetGet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek := []byte("0123456789abcdef0123456789abcdef")
	if err := s.SetKEK("key1", kek, 5*time.Minute); err != nil {
		t.Fatalf("SetKEK: %v", err)
	}

	got, err := s.GetKEK("key1")
	if err != nil {
		t.Fatalf("GetKEK: %v", err)
	}
	if got == nil {
		t.Fatal("GetKEK returned nil for existing key")
	}
	if len(got) != 32 {
		t.Fatalf("GetKEK length: got %d, want 32", len(got))
	}
}

func TestSessionStore_GetMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	got, err := s.GetKEK("nonexistent")
	if err != nil {
		t.Fatalf("GetKEK: %v", err)
	}
	if got != nil {
		t.Fatalf("GetKEK for missing key should return nil, got %v", got)
	}
}

func TestSessionStore_TTLExpiration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek := []byte("0123456789abcdef0123456789abcdef")
	if err := s.SetKEK("key1", kek, 50*time.Millisecond); err != nil {
		t.Fatalf("SetKEK: %v", err)
	}

	// Should be available immediately
	got, _ := s.GetKEK("key1")
	if got == nil {
		t.Fatal("GetKEK should return value before expiration")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	got, _ = s.GetKEK("key1")
	if got != nil {
		t.Fatal("GetKEK should return nil after expiration")
	}
}

func TestSessionStore_Clear(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek1 := []byte("0123456789abcdef0123456789abcdef")
	kek2 := []byte("abcdef0123456789abcdef0123456789")
	_ = s.SetKEK("key1", kek1, 5*time.Minute)
	_ = s.SetKEK("key2", kek2, 5*time.Minute)

	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	got1, _ := s.GetKEK("key1")
	got2, _ := s.GetKEK("key2")
	if got1 != nil || got2 != nil {
		t.Fatal("Clear should remove all entries")
	}
}

func TestSessionStore_ClearKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek1 := []byte("0123456789abcdef0123456789abcdef")
	kek2 := []byte("abcdef0123456789abcdef0123456789")
	_ = s.SetKEK("key1", kek1, 5*time.Minute)
	_ = s.SetKEK("key2", kek2, 5*time.Minute)

	if err := s.ClearKey("key1"); err != nil {
		t.Fatalf("ClearKey: %v", err)
	}

	got1, _ := s.GetKEK("key1")
	got2, _ := s.GetKEK("key2")
	if got1 != nil {
		t.Fatal("ClearKey should remove key1")
	}
	if got2 == nil {
		t.Fatal("ClearKey should not affect key2")
	}
}

func TestSessionStore_SetOverwrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek1 := []byte("0123456789abcdef0123456789abcdef")
	kek2 := []byte("abcdef0123456789abcdef0123456789")

	_ = s.SetKEK("key1", kek1, 5*time.Minute)

	// Get reference to internal entry before overwrite
	s.mu.RLock()
	oldEntry := s.entries["key1"]
	oldKEK := oldEntry.kek
	s.mu.RUnlock()

	_ = s.SetKEK("key1", kek2, 5*time.Minute)

	// Old KEK bytes should be zeroed
	allZero := true
	for _, b := range oldKEK {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("overwritten KEK bytes should be zeroed")
	}
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			kek := []byte("0123456789abcdef0123456789abcdef")
			_ = s.SetKEK("key1", kek, 5*time.Minute)
			_, _ = s.GetKEK("key1")
			_ = s.ClearKey("key1")
		}(i)
	}
	wg.Wait()
}

func TestSessionStore_StoresCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek := []byte("0123456789abcdef0123456789abcdef")
	_ = s.SetKEK("key1", kek, 5*time.Minute)

	// Modify the original — stored copy should be unaffected
	kek[0] = 0xFF

	got, _ := s.GetKEK("key1")
	if got[0] == 0xFF {
		t.Fatal("SessionStore should store a copy on Set, not a reference")
	}
}

func TestSessionStore_GetKEKReturnsCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewInMemorySessionStore(ctx)
	defer s.Stop()

	kek := []byte("0123456789abcdef0123456789abcdef")
	_ = s.SetKEK("key1", kek, 5*time.Minute)

	// Get a copy and mutate it
	got, _ := s.GetKEK("key1")
	got[0] = 0xFF

	// Re-get — stored value should be unaffected
	got2, _ := s.GetKEK("key1")
	if got2[0] == 0xFF {
		t.Fatal("GetKEK should return a defensive copy — mutating it must not affect the store")
	}
}
