package cmd

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/madstone-tech/cipher-core/internal/adapters/cli"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// keyJSON is one key in the JSON output of `keys create` and `keys list`.
// It holds public metadata only: no wrapped private key and no salt.
type keyJSON struct {
	ID          string     `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	PublicKey   []byte     `json:"public_key"` // base64 (encoding/json []byte)
	Type        string     `json:"type"`
	Alias       string     `json:"alias"`
	IsDefault   bool       `json:"is_default"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

func newKeyJSON(key *entities.IdentityKey) keyJSON {
	return keyJSON{
		ID:          key.ID,
		Fingerprint: key.Fingerprint,
		PublicKey:   key.PublicKey,
		Type:        string(key.Type),
		Alias:       key.Alias,
		IsDefault:   key.IsDefault,
		CreatedAt:   key.CreatedAt,
		ExpiresAt:   key.ExpiresAt,
	}
}

// keyCreateJSON is the JSON output of `keys create`: the key and its
// recovery phrase.
type keyCreateJSON struct {
	keyJSON
	RecoveryMnemonic        string `json:"recovery_mnemonic"`
	RecoveryMnemonicWarning string `json:"recovery_mnemonic_warning"`
}

type KeysCommand struct {
	dbPath     string
	jsonOutput bool
	verbose    bool

	// stdinIsTerminal and words are the terminal seams of the recovery
	// phrase confirmation; tests replace them.
	stdinIsTerminal func() bool
	words           wordPrompter
}

// wordPrompter reads one confirmation word.
type wordPrompter interface {
	PromptString(prompt string) (string, error)
}

func NewKeysCommand(dbPath string, jsonOutput bool, verbose bool) *KeysCommand {
	return &KeysCommand{
		dbPath:          dbPath,
		jsonOutput:      jsonOutput,
		verbose:         verbose,
		stdinIsTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		words:           cli.NewPrompter(),
	}
}

func (c *KeysCommand) List(ctx context.Context) error {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer adapters.Close() //nolint:errcheck // best-effort: read-only close (list only reads keys)

	manageKeys := usecases.NewManageKeys(adapters.KeyRepo, adapters.Logger)

	resp, err := manageKeys.ListKeys(ctx, &usecases.ListKeysRequest{
		Filters: usecases.KeyFilters{},
	})
	if err != nil {
		return err
	}

	if c.jsonOutput {
		keys := make([]keyJSON, 0, len(resp.Keys))
		for _, key := range resp.Keys {
			keys = append(keys, newKeyJSON(key))
		}
		data, err := json.MarshalIndent(keys, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal keys: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if len(resp.Keys) == 0 {
		fmt.Println("No keys found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tTYPE\tALIAS\tCREATED\tUSAGE\tDEFAULT\tEXPIRY"); err != nil {
		return fmt.Errorf("failed to write keys table: %w", err)
	}
	for _, key := range resp.Keys {
		defaultMark := ""
		if key.IsDefault {
			defaultMark = "✓"
		}
		expiryCol := expiryAnnotation(key)
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			key.ID,
			key.Type,
			key.Alias,
			key.CreatedAt.Format("2006-01-02"),
			key.UsageCount,
			defaultMark,
			expiryCol,
		); err != nil {
			return fmt.Errorf("failed to write keys table: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to write keys table: %w", err)
	}

	return nil
}

// ANSI colour codes for expiry warnings in the list output.
const (
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiReset  = "\033[0m"
)

// expiryAnnotation returns a human-readable expiry annotation for the keys
// list. Keys expiring within 1 day are shown in red; within 7 days in yellow.
func expiryAnnotation(key *entities.IdentityKey) string {
	if key.ExpiresAt == nil {
		return ""
	}
	if key.IsExpired() {
		return ansiRed + "EXPIRED" + ansiReset
	}
	daysLeft := time.Until(*key.ExpiresAt)
	days := int(math.Ceil(daysLeft.Hours() / 24))
	switch {
	case days <= 1:
		return ansiRed + fmt.Sprintf("⚠ Expires in %d day(s)", days) + ansiReset
	case days <= 7:
		return ansiYellow + fmt.Sprintf("⚠ Expires in %d days", days) + ansiReset
	default:
		return key.ExpiresAt.Format("2006-01-02")
	}
}

// Create creates a new key. expiresIn is a human-friendly duration string
// (e.g. "30d", "4w", "720h") and expiresAt is an RFC3339 absolute timestamp.
// At most one may be non-empty. Both default to "" (no expiry).
func (c *KeysCommand) Create(ctx context.Context, keyTypeStr, keyAlias, expiresIn, expiresAt, keyPassphrase string, skipConfirm bool) (retErr error) {
	// The recovery phrase confirmation needs a terminal. Without one, fail
	// before any key exists rather than leave an unconfirmed key behind.
	if !skipConfirm && !c.stdinIsTerminal() {
		return errors.New("no terminal to confirm the recovery phrase: pass --yes to skip the confirmation, and store the recovery phrase from the output")
	}

	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	createKey := usecases.NewCreateKey(adapters.KeyRepo, adapters.CryptoEngine, adapters.KEKProvider, adapters.SessionStore, newCLIPrompter(ctx, ""), adapters.Logger)

	var kt entities.KeyType
	switch keyTypeStr {
	case "x25519":
		kt = entities.KeyTypeX25519
	default:
		return fmt.Errorf("invalid key type: %s (must be x25519)", keyTypeStr)
	}

	// Resolve optional expiry.
	var expires *time.Time
	if expiresIn != "" && expiresAt != "" {
		return fmt.Errorf("--expires-in and --expires-at are mutually exclusive")
	}
	if expiresIn != "" {
		dur, err := ParseExpiryDuration(expiresIn)
		if err != nil {
			return fmt.Errorf("--expires-in: %w", err)
		}
		t := time.Now().Add(dur)
		expires = &t
	}
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return fmt.Errorf("--expires-at: expected RFC3339 format (e.g. 2026-12-31T00:00:00Z): %w", err)
		}
		if t.Before(time.Now()) {
			return fmt.Errorf("--expires-at: %s is in the past", expiresAt)
		}
		expires = &t
	}

	// Resolve passphrase from flag or env var.
	passphrase := keyPassphrase
	if passphrase == "" {
		passphrase = os.Getenv("MDSTN_KEY_PASSPHRASE")
	}

	resp, err := createKey.Execute(ctx, &usecases.CreateKeyRequest{
		Type:       kt,
		Alias:      keyAlias,
		Expires:    expires,
		Passphrase: passphrase,
	})
	if err != nil {
		return err
	}

	if !c.jsonOutput {
		fmt.Println()
		fmt.Println("Recovery phrase (24 words) — write this down and keep it safe:")
		fmt.Println()
		fmt.Println("  " + resp.Mnemonic)
		fmt.Println()
	}

	if !skipConfirm && !c.jsonOutput {
		if err := c.confirmPhrase(resp.Mnemonic); err != nil {
			return discardUnconfirmedKey(ctx, adapters.KeyRepo, resp.Key.ID, err)
		}
		fmt.Println("Recovery phrase confirmed.")
	}

	if c.jsonOutput {
		data, err := json.MarshalIndent(keyCreateJSON{
			keyJSON:                 newKeyJSON(resp.Key),
			RecoveryMnemonic:        resp.Mnemonic,
			RecoveryMnemonicWarning: recoveryMnemonicWarning,
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal key: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("✓ Created %s key\n", resp.Key.Type)
	fmt.Printf("ID: %s\n", resp.Key.ID)
	fmt.Printf("Fingerprint: %s\n", resp.Key.Fingerprint)
	if resp.Key.Alias != "" {
		fmt.Printf("Alias: %s\n", resp.Key.Alias)
	}
	if resp.Key.ExpiresAt != nil {
		fmt.Printf("Expires: %s\n", resp.Key.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

// confirmPhrase asks for 3 random words of mnemonic.
func (c *KeysCommand) confirmPhrase(mnemonic string) error {
	words := strings.Fields(mnemonic)
	positions, err := pickThreePositions(len(words))
	if err != nil {
		return fmt.Errorf("failed to pick confirmation positions: %w", err)
	}
	for _, pos := range positions {
		entered, err := c.words.PromptString(fmt.Sprintf("Enter word #%d: ", pos+1))
		if err != nil {
			return fmt.Errorf("failed to read confirmation word: %w", err)
		}
		if strings.TrimSpace(entered) != words[pos] {
			return fmt.Errorf("word #%d did not match", pos+1)
		}
	}
	return nil
}

// keyDeleter deletes a key by ID (usecases.KeyRepository, as `keys delete`).
type keyDeleter interface {
	Delete(ctx context.Context, id string) error
}

// discardUnconfirmedKey deletes the key id after its recovery phrase
// confirmation failed with cause, so no key without a confirmed backup stays.
// The key repository is used directly: `keys delete` refuses to delete the
// only default key.
func discardUnconfirmedKey(ctx context.Context, repo keyDeleter, id string, cause error) error {
	confirmErr := fmt.Errorf("recovery phrase confirmation failed: %w", cause)
	if err := repo.Delete(ctx, id); err != nil {
		return errors.Join(confirmErr,
			fmt.Errorf("failed to delete the unconfirmed key: %w", err),
			fmt.Errorf("key %s may still exist: delete it with `keys delete %s`, then run the command again", id, id))
	}
	return fmt.Errorf("%w: the key was NOT kept; run the command again", confirmErr)
}

// pickThreePositions picks 3 unique random positions from [0, n) using a
// partial Fisher-Yates shuffle with crypto/rand, returned in ascending order.
func pickThreePositions(n int) ([]int, error) {
	if n < 3 {
		return []int{}, nil
	}
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}
	for i := 0; i < 3; i++ {
		r, err := crand.Int(crand.Reader, big.NewInt(int64(n-i)))
		if err != nil {
			return nil, fmt.Errorf("crypto/rand: %w", err)
		}
		j := i + int(r.Int64())
		indices[i], indices[j] = indices[j], indices[i]
	}
	result := indices[:3]
	sort.Ints(result)
	return result, nil
}

func (c *KeysCommand) Delete(ctx context.Context, keyID string) (retErr error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	manageKeys := usecases.NewManageKeys(adapters.KeyRepo, adapters.Logger)

	if err := manageKeys.DeleteKey(ctx, &usecases.DeleteKeyRequest{
		ID: keyID,
	}); err != nil {
		return err
	}

	fmt.Printf("✓ Deleted key %s\n", keyID)
	return nil
}

func (c *KeysCommand) Alias(ctx context.Context, keyID, alias string) (retErr error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if cerr := adapters.Close(); cerr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close database: %w", cerr))
		}
	}()

	manageKeys := usecases.NewManageKeys(adapters.KeyRepo, adapters.Logger)

	if err := manageKeys.AliasKey(ctx, &usecases.AliasKeyRequest{
		ID:    keyID,
		Alias: alias,
	}); err != nil {
		return err
	}

	fmt.Printf("✓ Set alias '%s' for key %s\n", alias, keyID)
	return nil
}

func (c *KeysCommand) Export(ctx context.Context, keyID, keyFormat, outputPath string) error {
	if outputPath == "" {
		return fmt.Errorf("output path is required (use --output)")
	}

	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer adapters.Close() //nolint:errcheck // best-effort: read-only close (export only reads the key)

	manageKeys := usecases.NewManageKeys(adapters.KeyRepo, adapters.Logger)

	resp, err := manageKeys.ExportKey(ctx, &usecases.ExportKeyRequest{
		ID:     keyID,
		Format: keyFormat,
	})
	if err != nil {
		return err
	}

	if err := writeExport(outputPath, resp.Data, protectedKeyStores(c.dbPath)); err != nil {
		return err
	}

	fmt.Printf("✓ Exported key to %s\n", outputPath)
	return nil
}

// defaultKDServerURL is the hosted Cipher Key Directory that publish and
// unpublish target when no explicit server is configured (T007, FR-003).
const defaultKDServerURL = "https://keys.mdstn.dev"

// kdToken resolves the directory token: the explicit argument wins, then the
// KD_TOKEN environment variable (T006, FR-001). Empty resolution is an error
// naming both sources; nothing is sent to the network in that case.
func kdToken(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("KD_TOKEN"); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("no directory token: use --kd-token or set KD_TOKEN " +
		"(get one at https://keys.mdstn.dev by verifying your email)")
}

// resolveKDServerURL picks the publish/unpublish target: explicit flag, then
// CIPHER_SERVER_URL, then the hosted directory default.
func resolveKDServerURL(serverURL string) string {
	if serverURL != "" {
		return serverURL
	}
	if env := os.Getenv("CIPHER_SERVER_URL"); env != "" {
		return env
	}
	return defaultKDServerURL
}

// kdServerError turns a non-OK directory response into a classed error per
// the exit-code mapping (T020): 401/403 auth (exit 2), 409 conflict (exit 5),
// everything else generic (exit 1). The server body is relayed verbatim;
// neither the token nor key material is echoed.
func kdServerError(status int, respBody []byte) error {
	err := fmt.Errorf("key directory returned %d: %s", status, string(respBody))
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %w", err, entities.ErrUnauthorized)
	case http.StatusConflict:
		return fmt.Errorf("%w: %w", err, entities.ErrKDConflict)
	default:
		return err
	}
}

func (c *KeysCommand) Publish(ctx context.Context, keyEmail, serverURL string) error {
	return c.publish(ctx, keyEmail, serverURL, "", "")
}

// PublishWithToken publishes an explicit directory token (the --kd-token flag
// path). FR-001 precedence: flag > KD_TOKEN env > error.
func (c *KeysCommand) PublishWithToken(ctx context.Context, keyEmail, serverURL, token string) error {
	if token == "" {
		token = os.Getenv("KD_TOKEN")
	}
	return c.publish(ctx, keyEmail, serverURL, token, "")
}

// PublishWithTokenAndFingerprint sends the rotation / tombstone re-bind
// payload: the base body plus the current (or tombstone) fingerprint and the
// fingerprint_token proof-of-possession artifact (T009, FR-004, contract C1).
func (c *KeysCommand) PublishWithTokenAndFingerprint(ctx context.Context, keyEmail, serverURL, token, fingerprint string) error {
	if token == "" {
		token = os.Getenv("KD_TOKEN")
	}
	return c.publish(ctx, keyEmail, serverURL, token, fingerprint)
}

// publish is the shared publish path; token resolves FR-001 precedence and
// fingerprint (when non-empty) adds the rotation fields.
func (c *KeysCommand) publish(ctx context.Context, keyEmail, serverURL, token, fingerprint string) error {
	tok, err := kdToken(token)
	if err != nil {
		return err // no network sends without a token (FR-001)
	}
	serverURL = resolveKDServerURL(serverURL)

	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer adapters.Close() //nolint:errcheck // best-effort: read-only close (publish only reads keys)

	keys, err := adapters.KeyRepo.List(ctx, usecases.KeyFilters{Type: entities.KeyTypeX25519})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no X25519 key found — create one first with: cipher keys create")
	}

	var selectedKey *entities.IdentityKey
	for _, key := range keys {
		if key.IsDefault {
			selectedKey = key
			break
		}
	}
	if selectedKey == nil {
		selectedKey = keys[0]
	}

	body := map[string]interface{}{
		"email":      keyEmail,
		"public_key": base64.StdEncoding.EncodeToString(selectedKey.PublicKey),
	}
	if fingerprint != "" {
		body["fingerprint"] = fingerprint
		body["poc"] = map[string]string{"type": "fingerprint_token"}
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/ckd/publish", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("build publish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok) // FR-002

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- CLI request to a user-supplied server URL; not server-side request forgery in a local CLI context
	if err != nil {
		return fmt.Errorf("publish request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: read-only close

	if resp.StatusCode != http.StatusOK {
		respBody, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			return errors.Join(fmt.Errorf("server returned %d", resp.StatusCode), fmt.Errorf("read response body: %w", rerr))
		}
		return kdServerError(resp.StatusCode, respBody)
	}

	fmt.Printf("✓ Published key for %s\n", keyEmail)
	fmt.Printf("Key fingerprint: %s\n", selectedKey.Fingerprint)
	return nil
}

func (c *KeysCommand) Unpublish(ctx context.Context, keyEmail, serverURL string) error {
	return c.unpublishToken(ctx, keyEmail, serverURL, "")
}

// UnpublishWithToken unpublishes with an explicit token (the --kd-token flag
// path). FR-001 precedence: flag > KD_TOKEN env > error.
func (c *KeysCommand) UnpublishWithToken(ctx context.Context, keyEmail, serverURL, token string) error {
	return c.unpublishToken(ctx, keyEmail, serverURL, token)
}

func (c *KeysCommand) unpublishToken(ctx context.Context, keyEmail, serverURL, token string) error {
	tok, err := kdToken(token)
	if err != nil {
		return err // no network sends without a token (FR-001)
	}
	serverURL = resolveKDServerURL(serverURL)

	body := map[string]string{
		"email": keyEmail,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, serverURL+"/api/v1/ckd/unpublish", bytes.NewReader(bodyJSON)) // #nosec G704 -- CLI request to a user-supplied server URL; not SSRF in a local CLI context
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok) // FR-002

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- CLI request to a user-supplied server URL; not SSRF in a local CLI context
	if err != nil {
		return fmt.Errorf("unpublish request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: read-only close

	if resp.StatusCode != http.StatusOK {
		respBody, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			return errors.Join(fmt.Errorf("server returned %d", resp.StatusCode), fmt.Errorf("read response body: %w", rerr))
		}
		return kdServerError(resp.StatusCode, respBody)
	}

	fmt.Printf("✓ Unpublished key for %s\n", keyEmail)
	return nil
}

// Status reports whether a key fingerprint is published on the hosted
// directory (GET /api/v1/ckd/status, Bearer kd_token; live OpenAPI
// components/schemas/StatusResponse). Fingerprint precedence: explicit
// argument > default X25519 key from the local store. The fingerprint must be
// 64 lowercase hex characters (the server's query pattern); a positional
// fingerprint is normalized to lowercase before the request.
func (c *KeysCommand) Status(ctx context.Context, serverURL, token, fingerprint string) error {
	tok, err := kdToken(token)
	if err != nil {
		return err // no network sends without a token (FR-001)
	}
	serverURL = resolveKDServerURL(serverURL)

	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if fp != "" && !kdFingerprintPattern.MatchString(fp) {
		return fmt.Errorf("invalid fingerprint %q: want 64 hex characters", fp)
	}
	if fp == "" {
		selected, err := c.defaultX25519Key(ctx)
		if err != nil {
			return err
		}
		fp = strings.ToLower(selected.Fingerprint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		serverURL+"/api/v1/ckd/status?fingerprint="+url.PathEscape(fp), nil) // #nosec G704 -- CLI request to a user-supplied server URL; not SSRF in a local CLI context
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: read-only close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return kdServerError(resp.StatusCode, body)
	}

	var result struct {
		Published   bool   `json:"published"`
		Fingerprint string `json:"fingerprint"`
		EmailHash   string `json:"email_hash"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("invalid status response: %w", err)
	}

	fmt.Printf("Fingerprint: %s\n", result.Fingerprint)
	if result.Published {
		fmt.Println("✓ Published")
	} else {
		fmt.Println("Not published (unpublished, tombstoned within 30 days, or never published)")
	}
	return nil
}

// kdFingerprintPattern is the server's query-side fingerprint shape
// (OpenAPI: ^[0-9a-f]{64}$).
var kdFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// defaultX25519Key loads the default X25519 key from the local store (the
// same selection order as publish).
func (c *KeysCommand) defaultX25519Key(ctx context.Context) (*entities.IdentityKey, error) {
	adapters, err := NewCommonAdapters(c.dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer adapters.Close() //nolint:errcheck // best-effort: read-only close (status only reads keys)

	keys, err := adapters.KeyRepo.List(ctx, usecases.KeyFilters{Type: entities.KeyTypeX25519})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no X25519 key found — create one first with: cipher keys create, or pass a fingerprint")
	}
	for _, key := range keys {
		if key.IsDefault {
			return key, nil
		}
	}
	return keys[0], nil
}

// writeExport writes data to the explicit path outputPath through the staged
// writer: a 0600 temp file, published only when complete (a planted symlink at
// outputPath is replaced, not followed). An explicit path replaces an existing
// file, but never into a key database folder or over a directory (usecases.CheckOutputPath).
func writeExport(outputPath string, data []byte, keyStores []string) error {
	fh := cli.NewFileHandler()
	if err := usecases.CheckOutputPath(fh, "", outputPath, keyStores); err != nil {
		return err
	}
	w, err := fh.WriteStream(outputPath)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return errors.Join(fmt.Errorf("failed to write file: %w", err), w.Abort())
	}
	if err := w.Commit(); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

// protectedKeyStores returns the key databases that no CLI output may touch:
// the one in use (--db) and the default ~/.mdstn/cipher.db (T-9).
func protectedKeyStores(dbPath string) []string {
	stores := []string{dbPath}
	if home, err := os.UserHomeDir(); err == nil {
		stores = append(stores, filepath.Join(home, ".mdstn", "cipher.db"))
	}
	return stores
}
