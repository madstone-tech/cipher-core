package usecases

import (
	"context"
	"io"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// IdentityKeyRepository manages identity key storage and retrieval
type IdentityKeyRepository interface {
	Create(ctx context.Context, key *entities.IdentityKey) error
	GetByID(ctx context.Context, id string) (*entities.IdentityKey, error)
	GetByFingerprint(ctx context.Context, fingerprint string) (*entities.IdentityKey, error)
	GetDefault(ctx context.Context) (*entities.IdentityKey, error)
	List(ctx context.Context, filters KeyFilters) ([]*entities.IdentityKey, error)
	// ListMetadata returns blob-free key projections for listing surfaces
	// (HTTP keys list, CLI dropdowns, MCP list, expiry sweep).  The
	// full-material variants remain List / GetByID.
	ListMetadata(ctx context.Context, filters KeyFilters) ([]*entities.KeyMetadata, error)
	// ListWithExpiry returns all keys that have a non-null expires_at value,
	// regardless of user — used by the expiry checker to scan the full keyspace.
	ListWithExpiry(ctx context.Context) ([]*entities.IdentityKey, error)
	Update(ctx context.Context, key *entities.IdentityKey) error
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
}

// Deprecated: KeyRepository is the legacy interface name. Use IdentityKeyRepository.
type KeyRepository = IdentityKeyRepository

// KeyFilters for querying keys
type KeyFilters struct {
	Type      entities.KeyType
	Alias     string
	IsExpired *bool
	IsDefault *bool
	Limit     int
	Offset    int
}

// CKDCacheRepository manages local TOFU cache for CKD lookups
type CKDCacheRepository interface {
	Get(ctx context.Context, email string) (*CKDCacheEntry, error)
	Set(ctx context.Context, entry *CKDCacheEntry) error
	Delete(ctx context.Context, email string) error
}

// RecoveryKeyRepository stores the BIP39-derived Argon2id salt (once).
type RecoveryKeyRepository interface {
	Create(ctx context.Context, rk *entities.RecoveryKey) error
	Get(ctx context.Context) (*entities.RecoveryKey, error)
	Count(ctx context.Context) (int, error)
}

// CKDCacheEntry represents a cached CKD lookup
type CKDCacheEntry struct {
	Email       string
	PublicKey   []byte
	Fingerprint string
	FirstSeen   int64
	LastSeen    int64
}

// ============================================================================
// KEY WRAPPING PORTS
// ============================================================================

// KEKProvider derives key-encrypting keys from passphrases and wraps/unwraps
// private key material using AES-256-GCM.
type KEKProvider interface {
	// DeriveKEK derives a 32-byte KEK from a passphrase and salt using Argon2id.
	DeriveKEK(passphrase string, salt []byte) (kek []byte, err error)
	// GenerateSalt returns 16 cryptographically random bytes.
	GenerateSalt() ([]byte, error)
	// WrapKey encrypts privateKey with kek using AES-256-GCM.
	// AAD binds the blob to keyID ("mdstn-wrapped-key:<keyID>") making it
	// non-transferable between keys.
	// Returns nonce(12) || ciphertext.
	WrapKey(privateKey []byte, kek []byte, keyID string) ([]byte, error)
	// UnwrapKey decrypts wrapped bytes using kek.
	// AAD must bind the same keyID used at wrap time.
	// Returns an error on authentication failure (wrong passphrase) or key-ID mismatch.
	UnwrapKey(wrapped []byte, kek []byte, keyID string) ([]byte, error)
	// ZeroKEK overwrites all bytes of kek with zeros.
	ZeroKEK(kek []byte)
}

// SessionStore caches derived KEKs in memory with TTL-based expiration
// following an ssh-agent-style session pattern.
type SessionStore interface {
	// SetKEK stores a copy of the KEK bytes with the given TTL. ttl <= 0
	// selects the store's configured default TTL; usecases pass 0, so the
	// session lifetime is set in one place (the SDK's Config.SessionTTL).
	SetKEK(keyID string, kek []byte, ttl time.Duration) error
	// GetKEK returns the cached KEK if not expired, or nil if missing/expired.
	// Implementations MUST return a defensive copy safe to mutate and zero.
	GetKEK(keyID string) ([]byte, error)
	// Clear zeros all cached KEKs and removes all entries.
	Clear() error
	// ClearKey zeros and removes a single entry.
	ClearKey(keyID string) error
}

// ============================================================================
// CRYPTO PORTS
// ============================================================================

// CryptoEngine handles all cryptographic operations.
// AAD convention (header binding, see docs/format-spec.md): container operations pass the exact
// header bytes as aad; only headerless operations (key generation, recovery
// derivation) pass nil.
type CryptoEngine interface {
	// Symmetric encryption
	EncryptAES(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error)
	// EncryptAESWithNonce is the caller-nonce variant used by container paths:
	// the body nonce must exist before the header (carrying it) can
	// be serialized and bound as AAD.
	EncryptAESWithNonce(plaintext, key, nonce, aad []byte) (ciphertext []byte, err error)
	DecryptAES(ciphertext, key, nonce, aad []byte) (plaintext []byte, err error)

	// Streaming encryption (for files ≥ 1 MB). key is the payload key
	// (DerivePayloadKey); the stream follows the header MAC in the body.
	EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte) error
	DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, key, aad []byte) error

	// Header MAC and key schedule (docs/format-spec.md §Key schedule). The
	// file key is the CEK (method 2), the Argon2id output (method 3), or the
	// policy key (method 5).
	// HeaderMAC returns HMAC-SHA256(HKDF(fileKey, "mdstn-cipher/v2/header-mac"), headerAAD).
	HeaderMAC(fileKey, headerAAD []byte) ([]byte, error)
	// VerifyHeaderMAC compares headerMAC with HeaderMAC in constant time.
	VerifyHeaderMAC(fileKey, headerAAD, headerMAC []byte) (bool, error)
	// DerivePayloadKey returns HKDF(fileKey, "mdstn-cipher/v2/payload"), the
	// key that seals the body frames.
	DerivePayloadKey(fileKey []byte) ([]byte, error)

	// KEM-DEM wrapping (recipient blocks)
	// WrapCEK encrypts a content encryption key (CEK) for a recipient:
	// X25519 + HKDF-SHA256(salt = eph_pub || recipient_pub) + AES-GCM.
	// aad is the block AAD, entities.WrapCEKAAD.
	// Returns the ephemeral public key, nonce, and wrapped CEK (ciphertext).
	WrapCEK(cek, recipientPublicKey, aad []byte) (ephemeralPubKey, nonce, wrappedCEK []byte, err error)
	// UnwrapCEK decrypts a wrapped CEK using the recipient's private key.
	UnwrapCEK(wrappedCEK, ephemeralPubKey, nonce, privateKey, aad []byte) (cek []byte, err error)
	// ValidatePublicKey rejects a recipient public key that is not canonical:
	// not 32 bytes, bit 255 set, u ≥ 2^255 − 19, or a low-order point. A
	// failure matches entities.ErrInvalidRecipientKey.
	ValidatePublicKey(pub []byte) error

	// Hybrid encryption (X25519 + AES), for headerless key grants
	EncryptX25519(plaintext, recipientPublicKey, aad []byte) (ciphertext, ephemeralPubKey, nonce []byte, err error)
	DecryptX25519(ciphertext, ephemeralPubKey, nonce, privateKey, aad []byte) (plaintext []byte, err error)

	// Key generation
	GenerateAESKey() ([]byte, error)
	GenerateX25519Keypair() (publicKey, privateKey []byte, err error)
	GenerateMnemonic() (string, error)
	DeriveX25519FromMnemonic(mnemonic string) (publicKey, privateKey []byte, err error)

	// DeriveFileKeyArgon2id derives the method-3 file key:
	// Argon2id(password, salt, m=65536 KiB, t=3, p=4), 32 bytes. salt is 16 bytes.
	DeriveFileKeyArgon2id(password string, salt []byte) ([]byte, error)

	// Argon2id key derivation (for private key wrapping at rest — server-side only)
	DeriveKeyArgon2id(passphrase string) (key []byte, salt []byte, err error)

	// Hashing
	Hash(data []byte) string

	// IsValidMnemonic reports whether mnemonic is a valid BIP39 phrase.
	IsValidMnemonic(mnemonic string) bool
}

// Recipient represents a target for multi-recipient encryption.
type Recipient struct {
	PublicKey   []byte // 32-byte X25519 public key
	Fingerprint string // Full fingerprint (for messages only, never stored in the file)
}

// FileEncoder handles .mdstn file format encoding/decoding: container version
// 0x03 only.
type FileEncoder interface {
	// EncodeHeader serializes only the container header
	// ([magic][version=0x03][method][headerLen][headerJSON]).
	EncodeHeader(file *entities.EncryptedFile) ([]byte, error)
	// EncodeHeaderPlusBody serializes header+body into ONE buffer for a single
	// atomic WriteFile — the in-memory (chunked=false) path.
	EncodeHeaderPlusBody(file *entities.EncryptedFile, body []byte) ([]byte, error)
	Decode(data []byte) (*entities.EncryptedFile, error)
	// DecodeWithOffset also returns the raw header bytes (the AAD input,
	// [0:8+headerLen] of the received file) and the byte offset where the body begins.
	DecodeWithOffset(data []byte) (*entities.EncryptedFile, []byte, int64, error)
	// DecodeHeader reads exactly the header from r (8 bytes, then HeaderLen
	// bytes) and returns the file and headerAAD. It leaves r at the start of
	// the body.
	DecodeHeader(r io.Reader) (*entities.EncryptedFile, []byte, error)
}

// ============================================================================
// DISCOVERY PORTS
// ============================================================================

// CKDClient performs CKD key lookups
type CKDClient interface {
	LookupKey(ctx context.Context, email string) (*CKDPublicKey, error)
}

// CKDPublicKey represents a public key from CKD
type CKDPublicKey struct {
	Email       string
	PublicKey   []byte
	Fingerprint string
	CreatedAt   int64
}

// CKDPublisher publishes keys to CKD
type CKDPublisher interface {
	PublishKey(ctx context.Context, email string, publicKey []byte) error
	UnpublishKey(ctx context.Context, email string) error
}

// ============================================================================
// I/O PORTS
// ============================================================================

// FileHandler manages file system operations
type FileHandler interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
	ReadStream(path string) (io.ReadCloser, error)
	// WriteStream stages output for path. Nothing appears at path until the
	// returned writer's Commit succeeds; Abort discards the staged bytes.
	WriteStream(path string) (StagedWriter, error)
	// WriteStreamExclusive is WriteStream, but Commit fails with an error that
	// matches fs.ErrExist if path already exists, and then leaves path
	// unchanged. A decryptor uses it for an output path it chose itself.
	WriteStreamExclusive(path string) (StagedWriter, error)
	// SameFile reports whether a and b name the same existing file (after
	// links). It returns false, nil when either path does not exist.
	SameFile(a, b string) (bool, error)
	// IsDir reports whether path is an existing directory (after links).
	IsDir(path string) (bool, error)
	// Exists reports whether a file, directory, or link exists at path
	// (without following a final link).
	Exists(path string) (bool, error)
	// ResolvePath returns path with every symlink resolved, or path itself
	// when it does not exist.
	ResolvePath(path string) (string, error)
	// DirHoldsLink reports whether folder dir has an entry that is the same
	// file as file (a hard link). It is false when either does not exist.
	DirHoldsLink(dir, file string) (bool, error)
	CleanupStaleTempFiles(dir string) error
}

// StagedWriter buffers output in a temporary location and publishes it to the
// final path only on Commit.
//
// State table:
//   - open: Write appends; Commit publishes (→ committed); Abort discards (→ aborted).
//   - committed: Write errors; Commit and Abort are no-ops returning nil.
//   - aborted: Write and Commit error; Abort is a no-op returning nil.
type StagedWriter interface {
	io.Writer
	Commit() error
	Abort() error
}

// ProgressReporter reports operation progress
type ProgressReporter interface {
	ReportProgress(message string, percent int)
	ReportError(err error)
	ReportSuccess(message string)
}

// UserPrompter prompts user for input
type UserPrompter interface {
	PromptString(prompt string) (string, error)
	PromptConfirm(prompt string) (bool, error)
	PromptPassphrase(prompt string) (string, error)
}

// Logger provides structured logging
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	WithFields(fields map[string]interface{}) Logger
}

// ============================================================================
// CONFIG PORTS
// ============================================================================

// ConfigLoader loads and saves configuration
type ConfigLoader interface {
	LoadConfig() (*Config, error)
	SaveConfig(config *Config) error
}

// Config represents application configuration
type Config struct {
	ServerURL    string
	AuthMode     string // "local" or "oidc"
	OIDCIssuer   string
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
	UserEmail    string
	BackupDir    string
}

// PathResolver resolves standard paths
type PathResolver interface {
	ConfigDir() string
	DataDir() string
	CacheDir() string
}

// SharedKeyPolicyRepository manages shared key policies and per-grantee grants.
type SharedKeyPolicyRepository interface {
	CreatePolicy(ctx context.Context, policy *entities.SharedKeyPolicy) error
	GetPolicy(ctx context.Context, id string) (*entities.SharedKeyPolicy, error)
	ListPolicies(ctx context.Context, ownerID string) ([]*entities.SharedKeyPolicy, error)
	RevokePolicy(ctx context.Context, id string) error
	CreateGrant(ctx context.Context, grant *entities.SharedKeyGrant) error
	GetGrant(ctx context.Context, policyID, granteeID string) (*entities.SharedKeyGrant, error)
	ListGrants(ctx context.Context, policyID string) ([]*entities.SharedKeyGrant, error)
	ListGrantsForUser(ctx context.Context, granteeID string) ([]*entities.SharedKeyGrant, error)
	RevokeGrant(ctx context.Context, id string) error
}
