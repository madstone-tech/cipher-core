package crypto

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type sessionEntry struct {
	kek       []byte
	expiresAt time.Time
}

// InMemorySessionStore caches derived KEKs in memory with TTL-based expiration.
// It follows the ssh-agent pattern: KEKs are stored temporarily so users
// don't need to re-enter their passphrase for every operation.
type InMemorySessionStore struct {
	mu         sync.RWMutex
	entries    map[string]*sessionEntry
	cancel     context.CancelFunc
	defaultTTL time.Duration
}

// DefaultSessionTTL is the lifetime of a cached KEK when SetKEK gets ttl <= 0
// and SetDefaultTTL was not called.
const DefaultSessionTTL = 15 * time.Minute

// NewInMemorySessionStore creates a new session store and starts a background
// goroutine that prunes expired entries every 60 seconds. The pruner stops
// when the provided context is cancelled.
func NewInMemorySessionStore(ctx context.Context) *InMemorySessionStore {
	ctx, cancel := context.WithCancel(ctx)
	s := &InMemorySessionStore{
		entries:    make(map[string]*sessionEntry),
		cancel:     cancel,
		defaultTTL: DefaultSessionTTL,
	}
	go s.pruneLoop(ctx)
	return s
}

// SetDefaultTTL sets the TTL that SetKEK uses for ttl <= 0. A value <= 0
// selects DefaultSessionTTL.
func (s *InMemorySessionStore) SetDefaultTTL(ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultTTL = ttl
}

// SetKEK stores a copy of the KEK bytes with the given TTL; ttl <= 0 selects
// the store's default TTL (SetDefaultTTL). If an entry already exists for
// keyID, the old KEK is zeroed before replacement.
func (s *InMemorySessionStore) SetKEK(keyID string, kek []byte, ttl time.Duration) error {
	copied := make([]byte, len(kek))
	copy(copied, kek)

	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = s.defaultTTL
	}

	if existing, ok := s.entries[keyID]; ok {
		zeroBytes(existing.kek)
	}

	s.entries[keyID] = &sessionEntry{
		kek:       copied,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// GetKEK returns the cached KEK if it exists and has not expired.
// Returns (nil, nil) if the entry is missing or expired.
func (s *InMemorySessionStore) GetKEK(keyID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[keyID]
	if !ok {
		return nil, nil
	}
	if time.Now().After(entry.expiresAt) {
		return nil, nil
	}
	// Return a defensive copy to prevent races with the background pruner
	copied := make([]byte, len(entry.kek))
	copy(copied, entry.kek)
	return copied, nil
}

// Clear zeros all cached KEKs and removes all entries.
func (s *InMemorySessionStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range s.entries {
		zeroBytes(entry.kek)
		delete(s.entries, id)
	}
	return nil
}

// ClearKey zeros and removes a single entry.
func (s *InMemorySessionStore) ClearKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.entries[keyID]; ok {
		zeroBytes(entry.kek)
		delete(s.entries, keyID)
	}
	return nil
}

// Stop cancels the background pruner goroutine and clears all entries.
func (s *InMemorySessionStore) Stop() {
	s.cancel()
	if err := s.Clear(); err != nil {
		slog.Warn("session store clear on stop failed", "error", err)
	}
}

// pruneLoop runs every 60 seconds and removes expired entries,
// zeroing their KEK bytes before removal.
func (s *InMemorySessionStore) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pruneExpired()
		}
	}
}

func (s *InMemorySessionStore) pruneExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range s.entries {
		if now.After(entry.expiresAt) {
			zeroBytes(entry.kek)
			delete(s.entries, id)
		}
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
