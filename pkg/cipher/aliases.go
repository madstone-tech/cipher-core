package cipher

import "github.com/madstone-tech/cipher-core/internal/core/entities"

// Core types re-exported for code that cannot import internal packages —
// notably consuming applications that keep their own domain types but still
// speak in core keys and policies.
//
// Only types with real core consumers belong here. Application-specific UI
// types (PublicPage, Passkey, User, PageView, AuditEvent, Webhook, APIKey)
// have zero core consumers and must never be added.
type (
	// IdentityKey is a stored X25519 identity, wrapped at rest.
	IdentityKey = entities.IdentityKey
	// KeyMetadata is the blob-free list projection of IdentityKey.
	KeyMetadata = entities.KeyMetadata
	// SharedKeyPolicy governs team access to a shared key.
	SharedKeyPolicy = entities.SharedKeyPolicy
	// SharedKeyGrant is one recipient's access under a policy.
	SharedKeyGrant = entities.SharedKeyGrant
	// GrantStatus is a grant's lifecycle state.
	GrantStatus = entities.GrantStatus

	// StorageMode is the trust mode for private key storage.
	StorageMode = entities.StorageMode
	// StorageBackend is where key material is persisted.
	StorageBackend = entities.StorageBackend
)

// Recorded additions (constants) ------------------------------------------
// Justifying consumer: key repositories that store and branch on the trust
// mode and backend of every identity key row. They are part of the persisted
// IdentityKey contract, so refusing them would force those repositories to
// keep importing internal/core — exactly what the module boundary forbids.
const (
	// StorageModeStandard is the standard wrapped-at-rest mode.
	StorageModeStandard = entities.StorageModeStandard
	// StorageModeAdvanced is the client-held (zero-knowledge) mode.
	StorageModeAdvanced = entities.StorageModeAdvanced
	// StorageBackendSQLite selects the SQLite persistence backend.
	StorageBackendSQLite = entities.StorageBackendSQLite
	// StorageBackendPostgres selects the PostgreSQL persistence backend.
	StorageBackendPostgres = entities.StorageBackendPostgres
	// StorageBackendKeychain selects the macOS Keychain backend.
	StorageBackendKeychain = entities.StorageBackendKeychain
	// StorageBackendSecureEnclave selects the Secure Enclave backend.
	StorageBackendSecureEnclave = entities.StorageBackendSecureEnclave
	// GrantStatusActive marks a grant as usable. Justifying consumers:
	// repositories backing shared key policies.
	GrantStatusActive = entities.GrantStatusActive
	// GrantStatusRevoked marks a grant as revoked.
	GrantStatusRevoked = entities.GrantStatusRevoked
)

// Sentinel errors, re-exported so callers can use errors.Is without importing
// an internal package. These are the same values the repositories return, not
// copies — a copy would break errors.Is at every call site.
var (
	ErrNotFound      = entities.ErrNotFound
	ErrAlreadyExists = entities.ErrAlreadyExists
	ErrInvalidInput  = entities.ErrInvalidInput
	ErrUnauthorized  = entities.ErrUnauthorized

	// ErrHeaderAuthFailed matches a header, recipient block, or chunk that
	// failed authentication (a damaged or tampered container).
	ErrHeaderAuthFailed = entities.ErrHeaderAuthFailed
	// ErrNotARecipient matches a container that no available key can open.
	ErrNotARecipient = entities.ErrNotARecipient
	// ErrWrongPassword matches a passphrase-encrypted container that the
	// given file password does not open.
	ErrWrongPassword = entities.ErrWrongPassword
	// ErrInvalidRecipientKey matches a Recipient.PublicKey that is not a
	// usable X25519 public key (wrong length or a low-order point).
	ErrInvalidRecipientKey = entities.ErrInvalidRecipientKey
	// ErrKDConflict matches a key-directory publish or unpublish rejected on
	// binding-state grounds (current fingerprint required or mismatched).
	ErrKDConflict = entities.ErrKDConflict
	// ErrKDIntegrity matches a key-directory response that failed its
	// integrity check (signature, key id, or unknown key type).
	ErrKDIntegrity = entities.ErrKDIntegrity
)
