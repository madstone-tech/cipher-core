package cmd

import (
	"context"
	"io"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/pkg/cipherports"
)

// CommonAdapters holds pre-constructed adapter instances shared across
// multiple CLI commands. Each command invocation constructs its own
// CommonAdapters; instances are not safe for concurrent use across goroutines.
//
// Webhook delivery: CLI commands intentionally do NOT construct a
// WebhookDeliveryService or any AuditUseCase. Webhook delivery is a
// server-only concern (outside this module). A no-op dispatcher satisfies
// the WebhookDispatcher port without triggering real HTTP delivery when a
// future CLI path needs one.
type CommonAdapters struct {
	KeyRepo      cipherports.IdentityKeyRepository
	CryptoEngine cipherports.CryptoEngine
	KEKProvider  cipherports.KEKProvider
	SessionStore cipherports.SessionStore
	PolicyRepo   cipherports.SharedKeyPolicyRepository
	CKDClient    cipherports.CKDClient
	CKDCacheRepo cipherports.CKDCacheRepository
	Encoder      cipherports.FileEncoder
	Logger       cipherports.Logger

	// closer holds the SQLite connection closer. Stored separately so
	// KeyRepo can remain typed as the port interface.
	closer io.Closer
	// sessionStore holds the concrete type for Stop() on Close.
	sessionStoreImpl *crypto.InMemorySessionStore
}

// NewCommonAdapters constructs SQLite-backed common adapters for CLI commands.
// The caller MUST call Close() when the command finishes to release the
// underlying SQLite connection.
func NewCommonAdapters(dbPath string) (*CommonAdapters, error) {
	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		return nil, err
	}

	sessionStore := crypto.NewInMemorySessionStore(context.Background())

	policyRepo, err := sqlite.NewSharedKeyPolicyRepository(keyRepo.DB())
	if err != nil {
		return nil, err
	}

	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	ckdClient := ckd.NewClient(ckdCache)

	logger := logging.NewSimpleLogger()

	return &CommonAdapters{
		KeyRepo:          keyRepo,
		CryptoEngine:     crypto.NewEngine(),
		KEKProvider:      crypto.NewArgon2idKEKProvider(),
		SessionStore:     sessionStore,
		PolicyRepo:       policyRepo,
		CKDClient:        ckdClient,
		CKDCacheRepo:     ckdCache,
		Encoder:          crypto.NewFileEncoder(),
		Logger:           logger,
		closer:           keyRepo,
		sessionStoreImpl: sessionStore,
	}, nil
}

// Close releases the underlying SQLite connection.
// The error from the closer is returned and must not be swallowed.
func (ca *CommonAdapters) Close() error {
	if ca.sessionStoreImpl != nil {
		ca.sessionStoreImpl.Stop()
	}
	return ca.closer.Close()
}
