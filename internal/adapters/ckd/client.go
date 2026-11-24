package ckd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// Client implements the CKDClient interface
type Client struct {
	httpClient      *http.Client
	cache           usecases.CKDCacheRepository
	madstoneBaseURL string
}

// NewClient creates a new CKD client
func NewClient(cache usecases.CKDCacheRepository) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:           cache,
		madstoneBaseURL: "https://keys.mdstn.dev",
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
func (c *Client) LookupKeyFromURL(ctx context.Context, url, email string) (*usecases.CKDPublicKey, error) {
	return c.fetchKey(ctx, url, email)
}

// LookupKey looks up a public key via CKD protocol
func (c *Client) LookupKey(ctx context.Context, email string) (*usecases.CKDPublicKey, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// 1. Check local cache first (TOFU)
	if cached, err := c.cache.Get(ctx, email); err == nil {
		return &usecases.CKDPublicKey{
			Email:       cached.Email,
			PublicKey:   cached.PublicKey,
			Fingerprint: cached.Fingerprint,
			CreatedAt:   cached.FirstSeen,
		}, nil
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

	// 3. Try Madstone hosted directory
	if key, err := c.lookupFromMadstone(ctx, email); err == nil {
		c.cacheKey(ctx, email, key)
		return key, nil
	}

	// 4. Not found
	return nil, fmt.Errorf("no public key found for %s - ask them to run 'mdstn-cipher keys publish'", email)
}

// lookupFromDomain queries the domain's CKD endpoint
func (c *Client) lookupFromDomain(ctx context.Context, email, domain string) (*usecases.CKDPublicKey, error) {
	hash := hashEmail(email)
	url := fmt.Sprintf("https://%s/.well-known/mdstn-cipher/%s", domain, hash)

	return c.fetchKey(ctx, url, email)
}

// lookupFromMadstone queries the Madstone hosted directory
func (c *Client) lookupFromMadstone(ctx context.Context, email string) (*usecases.CKDPublicKey, error) {
	hash := hashEmail(email)
	url := fmt.Sprintf("%s/.well-known/mdstn-cipher/%s", c.madstoneBaseURL, hash)

	return c.fetchKey(ctx, url, email)
}

// fetchKey performs the HTTP request and parses the response
func (c *Client) fetchKey(ctx context.Context, url, email string) (*usecases.CKDPublicKey, error) {
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

	var result struct {
		Email       string `json:"email"`
		PublicKey   string `json:"public_key"` // base64
		Fingerprint string `json:"fingerprint"`
		CreatedAt   int64  `json:"created_at"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid CKD response: %w", err)
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
	}, nil
}

// cacheKey stores a key in the local cache
func (c *Client) cacheKey(ctx context.Context, email string, key *usecases.CKDPublicKey) {
	now := time.Now().Unix()
	entry := &usecases.CKDCacheEntry{
		Email:       email,
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
