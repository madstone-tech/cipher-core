package cipher

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	"github.com/madstone-tech/cipher-core/internal/adapters/sqlite"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// InMemory is a Config.DBPath that keeps the key database in memory: the
// client writes no database file and the keys go away on Close.
const InMemory = sqlite.InMemoryPath

// Config configures a Client with explicit dependencies. The zero-value is
// not usable; use New or NewLocal.
type Config struct {
	// DBPath is the SQLite database path. Empty selects the default
	// (~/.mdstn/cipher.db); InMemory selects a database with no file.
	DBPath string

	// CKDDirectoryURL overrides the CKD central directory base URL
	// (default: https://keys.madstone.dev). Empty string keeps the default.
	CKDDirectoryURL string

	// Logger receives structured log output. Defaults to a simple logger
	// that writes to stderr.
	Logger Logger

	// Progress, when set, receives progress callbacks from long operations.
	Progress ProgressReporter

	// SessionTTL bounds how long an unlocked KEK stays cached by Unlock.
	// Zero selects DefaultSessionTTL.
	SessionTTL time.Duration
}

// Client is the SDK entry point. It aggregates the port interfaces and
// constructs usecases over them. Secrets from a call's input are kept per
// call: two calls never share passphrase state. The key store and the session
// cache are shared, so Lock/LockAll end every caller's unlock.
type Client struct {
	keyRepo      usecases.IdentityKeyRepository
	recoveryRepo usecases.RecoveryKeyRepository
	cryptoEngine usecases.CryptoEngine
	kekProvider  usecases.KEKProvider
	sessionStore *crypto.InMemorySessionStore
	encoder      usecases.FileEncoder
	ckdClient    usecases.CKDClient
	ckdCache     usecases.CKDCacheRepository
	fileHandler  usecases.FileHandler
	logger       usecases.Logger
	progress     usecases.ProgressReporter
	sessionTTL   time.Duration
	dbPath       string // key database: no output may replace it
	createUC     *usecases.CreateKey
	manageUC     *usecases.ManageKeys
	lookupUC     *usecases.LookupKey
	publishUC    *usecases.PublishKey
	recoverUC    *usecases.RecoverKey
	storeWrap    *usecases.StoreWrappedKey

	// closer releases the SQLite connection when Close is called.
	closer io.Closer
}

// NewLocal constructs a zero-config client backed by embedded SQLite.
// An empty dbPath selects the default (~/.mdstn/cipher.db). The caller
// MUST call Close when finished.
func NewLocal(dbPath string) (*Client, error) {
	return New(Config{DBPath: dbPath})
}

// New constructs a client from explicit configuration. When Config.DBPath
// is empty, the default SQLite path is used; InMemory is kept as is and
// touches no file. The caller MUST call Close when finished.
func New(cfg Config) (*Client, error) {
	dbPath := cfg.DBPath
	if dbPath == "" {
		var err error
		if dbPath, err = defaultDBPath(); err != nil {
			return nil, err
		}
	}

	keyRepo, err := sqlite.NewIdentityKeyRepository(dbPath)
	if err != nil {
		return nil, err
	}

	sessionStore := crypto.NewInMemorySessionStore(context.Background())
	sessionStore.SetDefaultTTL(cfg.SessionTTL) // <= 0: DefaultSessionTTL
	ckdCache := sqlite.NewCKDCacheRepository(keyRepo.DB())
	recoveryRepo := sqlite.NewRecoveryKeyRepository(keyRepo.DB())

	var ckdClient usecases.CKDClient
	if cfg.CKDDirectoryURL != "" {
		ckdClient = ckd.NewClientWithBaseURL(cfg.CKDDirectoryURL)
	} else {
		ckdClient = ckd.NewClient(ckdCache)
	}

	// The default logger already satisfies the internal port, so it is used
	// directly; a caller-supplied one is bridged through the adapter.
	var logger usecases.Logger = logging.NewSimpleLogger()
	if cfg.Logger != nil {
		logger = loggerAdapter{inner: cfg.Logger}
	}

	var progress usecases.ProgressReporter = noopProgress{}
	if cfg.Progress != nil {
		progress = progressAdapter{inner: cfg.Progress}
	}

	sessionTTL := cfg.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}

	c := &Client{
		keyRepo:      keyRepo,
		recoveryRepo: recoveryRepo,
		cryptoEngine: crypto.NewEngine(),
		kekProvider:  crypto.NewArgon2idKEKProvider(),
		sessionStore: sessionStore,
		encoder:      crypto.NewFileEncoder(),
		ckdClient:    ckdClient,
		ckdCache:     ckdCache,
		fileHandler:  cli.NewFileHandler(),
		logger:       logger,
		progress:     progress,
		sessionTTL:   sessionTTL,
		dbPath:       dbPath,
		closer:       keyRepo,
	}

	// The key-management usecases read no passphrase from the prompter; they
	// get a stateless one. Encrypt and decrypt build their usecases per call
	// (encryptFile, decryptFile) with a prompter that holds that call's input.
	prompter := &headlessPrompter{}
	c.createUC = usecases.NewCreateKey(
		keyRepo, c.cryptoEngine, c.kekProvider, sessionStore,
		prompter, logger,
	)
	c.manageUC = usecases.NewManageKeys(keyRepo, logger)
	c.lookupUC = usecases.NewLookupKey(ckdClient, ckdCache, logger)
	c.publishUC = usecases.NewPublishKey(nil, keyRepo, logger)
	c.recoverUC = usecases.NewRecoverKey(
		c.kekProvider, keyRepo, c.cryptoEngine, prompter, logger,
	)
	c.storeWrap = usecases.NewStoreWrappedKey(keyRepo, logger)

	return c, nil
}

// encryptFile returns an EncryptFile usecase whose prompter answers with the
// key passphrase of one call only.
func (c *Client) encryptFile(keyPassphrase string) *usecases.EncryptFile {
	return usecases.NewEncryptFile(
		c.keyRepo, c.recoveryRepo, c.cryptoEngine, c.kekProvider,
		c.sessionStore, c.encoder, c.lookupUC,
		c.fileHandler, c.progress, &headlessPrompter{passphrase: keyPassphrase}, c.logger,
	).ProtectKeyStore(c.dbPath)
}

// decryptFile returns a DecryptFile usecase whose prompter answers with the
// key passphrase or recovery phrase of one call only.
func (c *Client) decryptFile(recoveryPassphrase string) *usecases.DecryptFile {
	return usecases.NewDecryptFile(
		c.keyRepo, c.cryptoEngine, c.kekProvider, c.sessionStore,
		c.encoder, c.fileHandler, c.progress, &headlessPrompter{passphrase: recoveryPassphrase}, c.logger,
	).ProtectKeyStore(c.dbPath)
}

// Close releases the underlying resources. The error must be handled or
// explicitly documented as safe to ignore.
func (c *Client) Close() error {
	c.sessionStore.Stop()
	return c.closer.Close()
}

// defaultDBPath returns the default SQLite path, matching the CLI's
// ~/.mdstn/cipher.db convention. The directory is created with 0700 perms.
// It fails when the home directory is unknown or ~/.mdstn cannot be created:
// a silent fallback to ./cipher.db would put wrapped private keys into the
// working directory, which can be a Git working copy (T-3). Pass
// Config.DBPath to choose a location.
func defaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cipher: no home directory for the default key database (set Config.DBPath): %w", err)
	}
	mdstDir := filepath.Join(home, ".mdstn")
	if err := os.MkdirAll(mdstDir, 0o700); err != nil {
		return "", fmt.Errorf("cipher: create %s (set Config.DBPath to use another location): %w", mdstDir, err)
	}
	return filepath.Join(mdstDir, "cipher.db"), nil
}

// validateRecipients checks each Recipient.PublicKey before any output is
// written. A failure matches ErrInvalidRecipientKey.
func validateRecipients(rs []Recipient) error {
	for i, r := range rs {
		if err := crypto.ValidatePublicKey(r.PublicKey); err != nil {
			return fmt.Errorf("recipient %d: %w", i, err)
		}
	}
	return nil
}

// noopProgress is the default ProgressReporter when none is injected.
type noopProgress struct{}

func (noopProgress) ReportProgress(string, int) {}
func (noopProgress) ReportError(error)          {}
func (noopProgress) ReportSuccess(string)       {}
