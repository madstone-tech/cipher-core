// Package cipherports re-exports the core port interfaces that code outside
// this module implements or consumes.
//
// It is separate from pkg/cipher deliberately. pkg/cipher.Logger is a trimmed
// four-method interface meant for Config — the ergonomic SDK surface — while
// the port below is the full five-method interface the usecases require. One
// package cannot hold both under the name Logger, and pkg/cipher should not
// become a home for plumbing interfaces most consumers never touch.
//
// Only ports with consumers outside this module belong here. Ports used
// solely by the server's own usecases live in internal/server/usecases instead.
package cipherports

import (
	"context"
	"net/http"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// AuthContextKey is an unexported context key type used by the auth providers.
type AuthContextKey string

// AuthUserContextKey is the context key under which *AuthenticatedUser is stored
// by any AuthProvider middleware. Auth middleware and adapters use this key.
const AuthUserContextKey AuthContextKey = "authenticated_user"

// UserIDContextKey is the context key under which the user's ID string is stored.
// Used by request handlers that need to resolve the acting user.
const UserIDContextKey AuthContextKey = "user_id"

// ============================================================================
// AUTH PORTS
// ============================================================================

// AuthProvider abstracts identity resolution across auth modes.
// Implementations resolve identity either from local accounts or from the
// hosted service's JWT claims, selected at server startup by configuration.
type AuthProvider interface {
	// Middleware returns chi-compatible HTTP middleware that extracts identity
	// from every request (cookie → header bridge + credential validation).
	// Stores *AuthenticatedUser in context if valid. Passes through unauthenticated
	// requests without rejection (rejection is enforced by requireAuth).
	Middleware() func(http.Handler) http.Handler

	// UserFromContext retrieves the authenticated user from the request context.
	// Returns nil if the request is unauthenticated or the credential is invalid.
	UserFromContext(ctx context.Context) *AuthenticatedUser

	// Mode returns the active auth mode string: "local", or the hosted
	// service's mode identifier when the server authenticates against the
	// hosted service.
	Mode() string
}

// PasswordVerifier verifies a user's password without exposing the hash or the
// underlying hashing algorithm. It is used by use cases that need to re-authenticate
// the user before destructive or high-risk operations.
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, email, password string) error
}

// AuthenticatedUser is the unified identity type used by all handlers.
// In local mode, Memberships is empty and Plan is always "free".
// In hosted-service mode, Memberships and Plan come from the JWT claims.
type AuthenticatedUser struct {
	UserID      string          // UUIDv4 or hex-encoded random ID (local) / hosted-service user ID
	Email       string          // Verified email address
	Plan        string          // "free" | "team" | "business" | "business_plus"
	Memberships []OrgMembership // Empty in local mode; populated from JWT claims in hosted-service mode
}

// OrgMembership represents a user's membership in one organisation (hosted-service mode only).
type OrgMembership struct {
	OrgID   string // Hosted-service organisation UUID
	OrgSlug string // URL-safe org identifier, e.g. "acme-corp"
	Role    string // "owner" | "admin" | "member"
	Plan    string // "free" | "team" | "business" | "business_plus"
}

// IsMemberOf returns true if the user belongs to the given orgID.
func (u *AuthenticatedUser) IsMemberOf(orgID string) bool {
	for _, m := range u.Memberships {
		if m.OrgID == orgID {
			return true
		}
	}
	return false
}

// HasRole returns true if the user has the given role in the given orgID.
// Role values: "owner" | "admin" | "member".
func (u *AuthenticatedUser) HasRole(orgID, role string) bool {
	for _, m := range u.Memberships {
		if m.OrgID == orgID && m.Role == role {
			return true
		}
	}
	return false
}

// HasPlan returns true if any of the user's org memberships are on the given plan.
// Plan values: "free" | "team" | "business" | "business_plus".
func (u *AuthenticatedUser) HasPlan(orgID, plan string) bool {
	for _, m := range u.Memberships {
		if m.OrgID == orgID && m.Plan == plan {
			return true
		}
	}
	return false
}

// PlanFeatureResolver reports whether a plan includes a named feature. It is
// set by the consuming application at startup (the application wires its
// commercial catalog into it). Core has no commercial surface —
// never import a plan catalog here.
//
// nil resolver ⇒ every feature reports false (safe default: unauthenticated/
// unconfigured deployments get no premium features).
var PlanFeatureResolver func(plan, feature string) bool

// HasFeature returns true if the user's top-level Plan includes the named feature.
// The plan→feature mapping is supplied by the consuming application (see
// PlanFeatureResolver).
func (u *AuthenticatedUser) HasFeature(feature string) bool {
	if PlanFeatureResolver == nil {
		return false
	}
	return PlanFeatureResolver(u.Plan, feature)
}

type (
	// Logger is the full structured-logging port, including WithFields.
	Logger = usecases.Logger
	// SessionStore caches derived KEKs with TTL expiry.
	SessionStore = usecases.SessionStore
	// KEKProvider derives, wraps and unwraps with Argon2id.
	KEKProvider = usecases.KEKProvider
	// IdentityKeyRepository stores and retrieves identity keys.
	IdentityKeyRepository = usecases.IdentityKeyRepository
	// CryptoEngine performs the primitive cryptographic operations. It
	// reads and writes container version 0x03 only.
	CryptoEngine = usecases.CryptoEngine
	// SharedKeyPolicyRepository stores team key policies and grants.
	SharedKeyPolicyRepository = usecases.SharedKeyPolicyRepository
	// UserPrompter prompts a human for input (used by team-key governance
	// flows that need re-authentication or passphrase entry). Kept here along
	// with the other core ports because internal/server/usecases.ManageTeamKeys
	// depends on it.
	UserPrompter = usecases.UserPrompter

	// Recorded additions (auth middleware and handlers) ----------------------
	// Justifying consumers: consuming applications' auth middleware and
	// handlers (all handlers authenticate via AuthenticatedUser and the
	// AuthUserContextKey/UserIDContextKey context keys; auth middleware and
	// rate limiter), application UI packages, and AuthProvider
	// implementations. These are usecases-level types that travel with the
	// core and are not confined to any delivery tree; they are not
	// server-bound.

	// Justifying consumers: consuming applications' handlers (keys, ckd,
	// public pages) construct and call the ManageKeys, PublishKey and
	// StoreWrappedKey usecases; application UI packages render their request
	// shapes.
	// ListKeysRequest filters the key listing.
	ListKeysRequest = usecases.ListKeysRequest
	// GetKeyRequest identifies one key to fetch.
	GetKeyRequest = usecases.GetKeyRequest
	// DeleteKeyRequest identifies one key to delete.
	DeleteKeyRequest = usecases.DeleteKeyRequest
	// ManageKeys is the key-management usecase.
	ManageKeys = usecases.ManageKeys
	// PublishKey publishes a public key for CKD discovery.
	PublishKey = usecases.PublishKey
	// PublishKeyRequest is a CKD publish request.
	// LookupKeyRequest / CreateKeyRequest: request shapes exposed to
	// consuming applications.
	LookupKeyRequest = usecases.LookupKeyRequest
	CreateKeyRequest = usecases.CreateKeyRequest
	// PublishKeyRequest is a CKD publish request.
	PublishKeyRequest = usecases.PublishKeyRequest
	// CKDPublisher stores published public keys.
	CKDPublisher = usecases.CKDPublisher
	// StoreWrappedKey stores a client-wrapped private key (ZK web flow).
	StoreWrappedKey = usecases.StoreWrappedKey
	// StoreWrappedKeyRequest is a wrapped-key store request.
	StoreWrappedKeyRequest = usecases.StoreWrappedKeyRequest
	// APIKeyCtx carries an authenticated API key through a request context.
	// Justifying consumer: consuming applications' auth middleware and API
	// key handlers.
	APIKeyCtx = usecases.APIKeyCtx

	// Justifying consumer: the CLI command wiring constructs the common
	// adapter set; these are core-travelling ports wired into every command.
	CKDCacheRepository = usecases.CKDCacheRepository
	// FileEncoder encodes and decodes container headers (version 0x03 only;
	// 0x01 and 0x02 fail with "unsupported version"). DecodeHeader reads a
	// header from a stream and leaves the reader at the start of the body.
	FileEncoder = usecases.FileEncoder
	// CKDClient performs Cipher Key Discovery lookups.
	CKDClient = usecases.CKDClient
)

// KeyFilters constrains IdentityKeyRepository.List queries. It is a plain
// struct, not an interface, but IdentityKeyRepository's List method is fixed
// to this exact core type — any implementation or fake outside this module
// must reference it through this alias rather than declaring its own, or it
// will not satisfy the interface.
type KeyFilters = usecases.KeyFilters

// Recorded additions (var aliases) ---------------------------------------
// Justifying consumers: consuming applications' auth middleware sets
// AuthUserContextKey and UserIDContextKey in request contexts; their
// handlers construct the ManageKeys, PublishKey and StoreWrappedKey
// usecases via these constructors.
var (
	// NewManageKeys constructs ManageKeys.
	NewManageKeys = usecases.NewManageKeys
	// NewCreateKey constructs CreateKey (consuming applications wire it
	// directly).
	NewCreateKey = usecases.NewCreateKey
	// NewLookupKey constructs LookupKey.
	NewLookupKey = usecases.NewLookupKey
	// NewPublishKey constructs PublishKey.
	NewPublishKey = usecases.NewPublishKey
	// NewStoreWrappedKey constructs StoreWrappedKey.
	NewStoreWrappedKey = usecases.NewStoreWrappedKey
)
