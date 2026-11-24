package ckd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// Publisher sends token-authenticated publish/unpublish/status requests to a
// Cipher Key Directory server. cmd (CLI) and pkg/cipher (SDK) both build on
// it so the wire behavior stays in one place.
//
// The zero value is unusable; NewPublisher applies the URL/token resolution
// rules. Error classes follow the release mapping: 401/403 carry
// entities.ErrUnauthorized, 409 carries entities.ErrKDConflict, everything
// else is a plain error. The token is never logged or echoed.
type Publisher struct {
	baseURL     string // resolved: explicit > CIPHER_SERVER_URL > production
	token       string // resolved: explicit > KD_TOKEN
	fingerprint string
	httpClient  *http.Client
}

// PublisherConfig gathers the CLI/SDK inputs for one directory publisher.
// All fields resolve per the release rules: empty falls back to environment
// and then the production default.
type PublisherConfig struct {
	// ServerURL is an explicit override (--server-url). Blank = env
	// (CIPHER_SERVER_URL) = production default.
	ServerURL string
	// Token is an explicit token (--kd-token). Blank = env (KD_TOKEN).
	// Both blank: NewPublisher fails before any request is possible.
	Token string
	// Fingerprint is the rotation factor for publish (--fingerprint).
	Fingerprint string
}

// NewPublisher resolves cfg. It fails with guidance when no token source
// exists (FR-001: nothing is sent without a token).
func NewPublisher(cfg PublisherConfig) (*Publisher, error) {
	token := cfg.Token
	if token == "" {
		token = os.Getenv("KD_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("no directory token: use --kd-token or set KD_TOKEN " +
			"(get one at https://keys.mdstn.dev by verifying your email)")
	}
	base := cfg.ServerURL
	if base == "" {
		base = os.Getenv("CIPHER_SERVER_URL")
	}
	if base == "" {
		base = DefaultMadstoneBaseURL
	}
	return &Publisher{
		baseURL:     strings.TrimRight(base, "/"),
		token:       token,
		fingerprint: cfg.Fingerprint,
		httpClient:  http.DefaultClient,
	}, nil
}

// publishResponse is the server's success shape (PublishResponse).
type publishResponse struct {
	Status    string `json:"status"`
	Email     string `json:"email"`
	EmailHash string `json:"email_hash"`
	Rotated   bool   `json:"rotated,omitempty"`
	Rebound   bool   `json:"rebound,omitempty"`
}

// PublishResult carries what the caller shows after a publish: the
// fingerprint-index hash and whether the call rotated or re-bound an
// existing binding.
type PublishResult struct {
	EmailHash string
	Rotated   bool
	Rebound   bool
}

// Publish sends POST /api/v1/ckd/publish with the Bearer token. Fresh
// bindings need only email + publicKey; a pinned binding requires the
// server-provided current fingerprint (the request then carries fingerprint
// and the fingerprint_token poc). The server's 409 surfaces the required
// fingerprint in its body; relay it with guidance rather than retrying.
func (p *Publisher) Publish(ctx context.Context, email string, publicKey []byte, fingerprint string) (*usecases.PublishResult, error) {
	body := map[string]interface{}{
		"email":      email,
		"public_key": base64.StdEncoding.EncodeToString(publicKey),
	}
	// The fingerprint argument wins; the client-configured rotation factor
	// (PublishFingerprint in the SDK, --fingerprint in the CLI) applies when
	// the argument is blank.
	if fingerprint == "" {
		fingerprint = p.fingerprint
	}
	if fingerprint != "" {
		body["fingerprint"] = fingerprint
		body["poc"] = map[string]string{"type": "fingerprint_token"}
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal publish request: %w", err)
	}

	out, err := p.do(ctx, http.MethodPost, "/api/v1/ckd/publish", bodyJSON)
	if err != nil {
		return nil, err
	}
	var resp publishResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("invalid publish response: %w", err)
	}
	return &usecases.PublishResult{
		EmailHash: resp.EmailHash,
		Rotated:   resp.Rotated,
		Rebound:   resp.Rebound,
	}, nil
}

// Unpublish sends DELETE /api/v1/ckd/unpublish (idempotent server-side).
func (p *Publisher) Unpublish(ctx context.Context, email string) error {
	bodyJSON, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return fmt.Errorf("marshal unpublish request: %w", err)
	}
	_, err = p.do(ctx, http.MethodDelete, "/api/v1/ckd/unpublish", bodyJSON)
	return err
}

// kdFingerprintShape is the server's fingerprint query pattern
// (OpenAPI: ^[0-9a-f]{64}$).
var kdFingerprintShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Status sends GET /api/v1/ckd/status?fingerprint=...
func (p *Publisher) Status(ctx context.Context, fingerprint string) (*usecases.CKDStatusResult, error) {
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if !kdFingerprintShape.MatchString(fp) {
		return nil, fmt.Errorf("invalid fingerprint %q: want 64 hex characters", fp)
	}
	out, err := p.do(ctx, http.MethodGet, "/api/v1/ckd/status?fingerprint="+fp, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Published   bool   `json:"published"`
		Fingerprint string `json:"fingerprint"`
		EmailHash   string `json:"email_hash"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("invalid status response: %w", err)
	}
	return &usecases.CKDStatusResult{
		Published:   resp.Published,
		Fingerprint: resp.Fingerprint,
		EmailHash:   resp.EmailHash,
	}, nil
}

// do runs one authenticated request and maps non-OK responses to classed
// errors (401/403 auth, 409 conflict, rest generic). The body of a failed
// response is relayed verbatim; token and key material never appear.
func (p *Publisher) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build directory request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("directory request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: read-only close

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return respBody, nil
	}
	err = fmt.Errorf("key directory returned %d: %s", resp.StatusCode, string(respBody))
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: %w", err, entities.ErrUnauthorized)
	case http.StatusConflict:
		return nil, fmt.Errorf("%w: %w", err, entities.ErrKDConflict)
	default:
		return nil, err
	}
}
