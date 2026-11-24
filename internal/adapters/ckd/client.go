package ckd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// Client implements the CKDClient interface
type Client struct {
	httpClient      *http.Client
	cache           usecases.CKDCacheRepository
	madstoneBaseURL string
}

// DefaultMadstoneBaseURL is the production hosted directory. Pin here and in
// docs/ckd-protocol.md; CIPHER_CKD_URL may override it per environment.
const DefaultMadstoneBaseURL = "https://keys.mdstn.dev"

// NewClient creates a new CKD client
func NewClient(cache usecases.CKDCacheRepository) *Client {
	base := DefaultMadstoneBaseURL
	// CIPHER_CKD_URL overrides the hosted-directory base for non-production
	// directories (staging, local mode). Blank = the pinned production URL.
	if env := os.Getenv("CIPHER_CKD_URL"); env != "" {
		base = env
	}
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:           cache,
		madstoneBaseURL: base,
	}
}

// NewClientWithBaseURL creates a CKD client with a custom base URL (for testing).
// A nil cache disables TOFU caching.
func NewClientWithBaseURL(baseURL string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		madstoneBaseURL: baseURL,
	}
}

// LookupKeyFromURL performs a CKD lookup against a specific URL (for testing).
// Unsigned: tests drive the signature path through lookupFromMadstone.
func (c *Client) LookupKeyFromURL(ctx context.Context, url, email string) (*usecases.CKDPublicKey, error) {
	return c.fetchKey(ctx, url, email, nil)
}

// LookupKey looks up a public key via CKD protocol
func (c *Client) LookupKey(ctx context.Context, email string) (*usecases.CKDPublicKey, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// 1. Check local cache first (TOFU). A nil cache skips the cache stages.
	if c.cache != nil {
		if cached, err := c.cache.Get(ctx, email, ""); err == nil {
			keyType := cached.KeyType
			if keyType == "" {
				keyType = usecases.DefaultCKDKeyType
			}
			return &usecases.CKDPublicKey{
				Email:       cached.Email,
				PublicKey:   cached.PublicKey,
				Fingerprint: cached.Fingerprint,
				CreatedAt:   cached.FirstSeen,
				KeyType:     keyType,
			}, nil
		}
	}

	// 2. Try domain CKD lookup
	domain := extractDomain(email)
	if domain != "" {
		if key, err := c.lookupFromDomain(ctx, email, domain); err == nil {
			// Cache the result
			c.cacheKey(ctx, email, key)
			return key, nil
		}
	}

	// 3. Try Madstone hosted directory. Integrity failures (tampered or
	// unsigned responses, unknown service key id) surface instead of collapsing
	// into "not found": a failed check is evidence, not absence (US3 acc. 2).
	key, err := c.lookupFromMadstone(ctx, email)
	if err == nil {
		c.cacheKey(ctx, email, key)
		return key, nil
	}
	if errors.Is(err, entities.ErrKDIntegrity) {
		return nil, err
	}

	// 4. Not found
	return nil, fmt.Errorf("no public key found for %s - ask them to run 'mdstn-cipher keys publish'", email)
}

// lookupFromDomain queries the domain's CKD endpoint
func (c *Client) lookupFromDomain(ctx context.Context, email, domain string) (*usecases.CKDPublicKey, error) {
	hash := hashEmail(email)
	url := fmt.Sprintf("https://%s/.well-known/mdstn-cipher/%s", domain, hash)

	return c.fetchKey(ctx, url, email, nil) // domain lookups unsigned (contract C3)
}

// lookupFromMadstone queries the Madstone hosted directory. Responses are
// signature-verified before acceptance (FR-005): the madstone-only signing
// scheme applies here, while domain lookups run unsigned per contract C3.
func (c *Client) lookupFromMadstone(ctx context.Context, email string) (*usecases.CKDPublicKey, error) {
	hash := hashEmail(email)
	url := fmt.Sprintf("%s/.well-known/mdstn-cipher/%s", c.madstoneBaseURL, hash)

	return c.fetchKey(ctx, url, email, &signatureCheck{emailHash: hash})
}

// signatureCheck carries the signed-response verification inputs for a fetch.
// A nil check disables verification (domain lookups, tests).
type signatureCheck struct {
	emailHash string // covered content = emailHash + "\n" + body
}

// fetchKey performs the HTTP request and parses the response. When sig is
// non-nil the response must carry a valid X-Mdstn-Kd-Signature before any
// decode or cache write happens (FR-005).
func (c *Client) fetchKey(ctx context.Context, url, email string, sig *signatureCheck) (*usecases.CKDPublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: read-only close

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("key not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CKD lookup failed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Integrity gate (FR-005): verify before decode; nothing from a failed
	// response is used or cached.
	if sig != nil {
		if err := verifyKDResponse(sig.emailHash, body, resp.Header.Get(HeaderSignature), resp.Header.Get(HeaderKeyID)); err != nil {
			return nil, err
		}
	}

	var result struct {
		Email       string `json:"email"`
		PublicKey   string `json:"public_key"` // base64
		Fingerprint string `json:"fingerprint"`
		CreatedAt   int64  `json:"created_at"`
		KeyType     string `json:"key_type"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid CKD response: %w", err)
	}

	// key_type handling (FR-007): absent ⇒ default; unknown ⇒ surfaced, and
	// the response is rejected before any cache write.
	keyType := result.KeyType
	if keyType == "" {
		keyType = usecases.DefaultCKDKeyType
	}
	if keyType != usecases.DefaultCKDKeyType {
		return nil, fmt.Errorf("%w: response declares unsupported key type %q (supported: %q)", entities.ErrKDIntegrity, keyType, usecases.DefaultCKDKeyType)
	}

	// Decode base64 public key — the CKD response carries a base64-encoded key,
	// NOT the raw ASCII bytes of the base64 string.
	pubKey, err := base64.StdEncoding.DecodeString(result.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key from CKD: %w", err)
	}

	return &usecases.CKDPublicKey{
		Email:       email,
		PublicKey:   pubKey,
		Fingerprint: result.Fingerprint,
		CreatedAt:   result.CreatedAt,
		KeyType:     keyType,
	}, nil
}

// cacheKey stores a key in the local cache
func (c *Client) cacheKey(ctx context.Context, email string, key *usecases.CKDPublicKey) {
	if c.cache == nil {
		return
	}
	now := time.Now().Unix()
	entry := &usecases.CKDCacheEntry{
		Email:       email,
		KeyType:     key.KeyType,
		PublicKey:   key.PublicKey,
		Fingerprint: key.Fingerprint,
		FirstSeen:   now,
		LastSeen:    now,
	}

	// Attempt to cache but don't fail the lookup if it doesn't work
	if err := c.cache.Set(ctx, entry); err != nil {
		slog.Warn("failed to cache CKD key", "error", err)
	}
}

// hashEmail creates SHA-256 hash of lowercase email
func hashEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
