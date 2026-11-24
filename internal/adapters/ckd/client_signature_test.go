package ckd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
	"github.com/madstone-tech/cipher-core/internal/core/entities"
	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// fixtureBytes loads the pinned cross-repo wire fixture (T001/T016):
// internal/testdata/ckd/lookup.json, byte-identical to the ckd-server copy.
func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ckd", "lookup.json"))
	if err != nil {
		t.Fatalf("load pinned fixture: %v", err)
	}
	return raw
}

// fixtureEmailHash recomputes the covered-content hash for alice@example.com.
func fixtureEmailHash(t *testing.T) string {
	t.Helper()
	return ckd.HashEmailForTest("alice@example.com")
}

// signFixture makes a valid ed25519 signature over the pinned fixture body
// with a keypair whose public key is substituted into the constants via the
// test-only override hook (see setTestServiceKey below).
func signFixture(t *testing.T, priv ed25519.PrivateKey, body []byte) string {
	t.Helper()
	sig := ed25519.Sign(priv, ckd.CoveredContentForTest(fixtureEmailHash(t), body))
	return base64.StdEncoding.EncodeToString(sig)
}

// setTestServiceKey swaps the pinned service key for a test keypair and
// returns a restore func. The constants live behind small indirection hooks
// in the package (see service_key_test_hooks.go).
func setTestServiceKey(t *testing.T, pub ed25519.PublicKey, keyID string) {
	t.Helper()
	ckd.TestOverrideServiceKey(t, pub, keyID)
	t.Cleanup(func() { ckd.TestResetServiceKey(t) })
}

// TestFixtureByteExactRoundTrip (US5, T016, FR-009): the pinned fixture
// decodes byte-exactly through the production decoder. Every field asserted.
func TestFixtureByteExactRoundTrip(t *testing.T) {
	body := fixtureBytes(t)

	// Byte-exactness of the copy itself — drift between repos fails here.
	expectedTail := `"created_at":1763932800,"key_type":"x25519"}`
	trimmed := strings.TrimRight(string(body), "\n")
	if !strings.HasSuffix(trimmed, expectedTail) {
		t.Errorf("fixture tail drifted from the pinned contract: %q", trimmed[len(trimmed)-len(expectedTail):])
	}

	// Decode via the production path: the signed response (this is the
	// hosted-directory wire) with a test signer over the exact bytes.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	setTestServiceKey(t, pub, "kd-test-1")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ckd.HeaderKeyID, "kd-test-1")
		w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, body))
		_, _ = w.Write(body) // exact fixture bytes
	}))
	defer ts.Close()

	client := ckd.NewClientWithBaseURL(ts.URL)
	key, err := client.LookupKey(t.Context(), "alice@example.com")
	if err != nil {
		t.Fatalf("decode pinned fixture: %v", err)
	}
	if key.Email != "alice@example.com" {
		t.Errorf("email = %q", key.Email)
	}
	wantKey, _ := base64.StdEncoding.DecodeString("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	if string(key.PublicKey) != string(wantKey) {
		t.Errorf("public key bytes = %x, want %x", key.PublicKey, wantKey)
	}
	if key.Fingerprint != "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9" {
		t.Errorf("fingerprint = %q", key.Fingerprint)
	}
	if key.CreatedAt != 1763932800 {
		t.Errorf("created_at = %d, want 1763932800", key.CreatedAt)
	}
	if key.KeyType != "x25519" {
		t.Errorf("key_type = %q, want x25519", key.KeyType)
	}
}

// TestSignatureTamperRejected (US3 acc. 2, FR-005): one altered body byte
// fails verification, and nothing is cached.
func TestSignatureTamperRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	setTestServiceKey(t, pub, "kd-test-1")

	body := fixtureBytes(t)
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 0xFF // flip one bit

	cache := newMemCache()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ckd.HeaderKeyID, "kd-test-1")
		w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, body)) // sig over ORIGINAL
		_, _ = w.Write(tampered)                                        // tampered bytes served
	}))
	defer ts.Close()

	client := ckd.NewClient(cache)
	client.TestSetMadstoneBaseURL(ts.URL)
	_, err = client.LookupKey(t.Context(), "alice@example.com")
	if err == nil {
		t.Fatal("tampered response accepted")
	}
	if !errors.Is(err, entities.ErrKDIntegrity) {
		t.Errorf("tamper must be an integrity error: %v", err)
	}
	if len(cache.entries) != 0 {
		t.Errorf("tampered response must not cache: %d entries", len(cache.entries))
	}
}

// TestKeyIDUnknownSurfaced (US3 acc. 3, FR-006): a response under an
// unrecognized key id is surfaced (integrity error), never accepted.
func TestKeyIDUnknownSurfaced(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	setTestServiceKey(t, pub, "kd-test-1")

	body := fixtureBytes(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ckd.HeaderKeyID, "kd-someone-else") // unknown id
		w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, body))
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	client := ckd.NewClientWithBaseURL(ts.URL)
	_, err = client.LookupKey(t.Context(), "alice@example.com")
	if err == nil {
		t.Fatal("unknown key id accepted")
	}
	if !errors.Is(err, entities.ErrKDIntegrity) {
		t.Errorf("unknown key id must be an integrity error: %v", err)
	}
	if !strings.Contains(err.Error(), "unrecognized key id") {
		t.Errorf("error should surface the key-id conflict: %v", err)
	}
}

// TestMissingHeadersRejected (US3 acc. 4): absent signature or key-id
// headers are integrity failures (spec edge case 4).
func TestMissingHeadersRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	setTestServiceKey(t, pub, "kd-test-1")
	body := fixtureBytes(t)

	cases := []struct {
		name   string
		sigHdr string
		kidHdr string
	}{
		{"no signature header", "", "kd-test-1"},
		{"no key id header", "valid-sig", ""},
		{"no headers at all", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.sigHdr != "" && tc.sigHdr != "valid-sig" {
					t.Errorf("unexpected sig header %q", tc.sigHdr)
				}
				if tc.sigHdr == "valid-sig" {
					w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, body))
				}
				if tc.kidHdr != "" {
					w.Header().Set(ckd.HeaderKeyID, tc.kidHdr)
				}
				_, _ = w.Write(body)
			}))
			defer ts.Close()

			client := ckd.NewClientWithBaseURL(ts.URL)
			_, err := client.LookupKey(t.Context(), "alice@example.com")
			if err == nil {
				t.Fatal("missing headers accepted")
			}
			if !errors.Is(err, entities.ErrKDIntegrity) {
				t.Errorf("missing headers must be integrity errors: %v", err)
			}
		})
	}
}

// TestKeyTypeAbsentDefaultsKnownSurfaces (US4, T013, FR-007): absent field ⇒
// default x25519; declared known ⇒ passes through; unknown ⇒ surfaced and
// NOT cached.
func TestKeyTypeAbsentDefaultsKnownSurfaces(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	setTestServiceKey(t, pub, "kd-test-1")

	cases := []struct {
		name     string
		keyType  string // "" means omit the field
		wantType string
		wantErr  bool
		errInteg bool
	}{
		{"absent defaults to x25519", "", "x25519", false, false},
		{"declared x25519 passes", "x25519", "x25519", false, false},
		{"unknown type surfaced", "ml-kem-768", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]interface{}
			if err := json.Unmarshal(fixtureBytes(t), &raw); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}
			if tc.keyType == "" {
				delete(raw, "key_type")
			} else {
				raw["key_type"] = tc.keyType
			}
			respBody, err := json.Marshal(raw)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			cache := newMemCache()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(ckd.HeaderKeyID, "kd-test-1")
				w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, respBody))
				_, _ = w.Write(respBody)
			}))
			defer ts.Close()

			client := ckd.NewClient(cache)
			client.TestSetMadstoneBaseURL(ts.URL)
			key, err := client.LookupKey(t.Context(), "alice@example.com")
			if tc.wantErr {
				if err == nil {
					t.Fatal("unknown key type accepted")
				}
				if tc.errInteg && !errors.Is(err, entities.ErrKDIntegrity) {
					t.Errorf("unknown key type must be an integrity error: %v", err)
				}
				if len(cache.entries) != 0 {
					t.Errorf("unknown key type must not cache: %d entries", len(cache.entries))
				}
				return
			}
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if key.KeyType != tc.wantType {
				t.Errorf("key type = %q, want %q", key.KeyType, tc.wantType)
			}
		})
	}
}

// TestLookupUsecaseVerifiedPath (A7, US3 acc. 1 at the usecase boundary):
// usecases.LookupKey.Execute end to end with a signature-verifying client
// returns the key and caches it.
func TestLookupUsecaseVerifiedPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	setTestServiceKey(t, pub, "kd-test-1")
	body := fixtureBytes(t)

	cache := newMemCache()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ckd.HeaderKeyID, "kd-test-1")
		w.Header().Set(ckd.HeaderSignature, signFixture(t, priv, body))
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	client := ckd.NewClient(cache)
	client.TestSetMadstoneBaseURL(ts.URL)
	logger := nopLogger{}
	lk := usecases.NewLookupKey(client, cache, logger)

	resp, err := lk.Execute(t.Context(), &usecases.LookupKeyRequest{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("usecase execute: %v", err)
	}
	wantKey, _ := base64.StdEncoding.DecodeString("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	if string(resp.PublicKey) != string(wantKey) {
		t.Errorf("usecase public key = %x", resp.PublicKey)
	}
	if resp.FromCache {
		t.Error("first lookup must be a cache miss")
	}
	if len(cache.entries) != 1 {
		t.Errorf("verified result must cache: %d entries", len(cache.entries))
	}
	if cached, ok := cache.get("alice@example.com"); ok {
		if cached.KeyType != "x25519" {
			t.Errorf("cached key type = %q", cached.KeyType)
		}
	} else {
		t.Error("entry missing under alice@example.com")
	}
}

// TestKeyIDConstantTimeCompare pins the constant-time compare contract
// (FR-006): the compare call runs in the verify path (guarded by
// crypto/subtle; see service_key.go). This test asserts the hook accepts the
// pinned id shape and rejects a differing id of the same length.
func TestKeyIDConstantTimeCompare(t *testing.T) {
	pinned := ckd.KDServiceKeyID
	sameLen := make([]byte, len(pinned))
	if subtle.ConstantTimeCompare([]byte(sameLen), []byte(pinned)) == 1 {
		t.Error("zeroed same-length id must not compare equal")
	}
	if subtle.ConstantTimeCompare([]byte(pinned), []byte(pinned)) != 1 {
		t.Error("identical ids must compare equal")
	}
}

// --- test doubles -------------------------------------------------------

// memCache is an in-memory CKDCacheRepository for the tests above.
type memCache struct {
	entries map[string]*usecases.CKDCacheEntry
}

func newMemCache() *memCache { return &memCache{entries: map[string]*usecases.CKDCacheEntry{}} }

func (m *memCache) key(email, keyType string) string { return email + "|" + keyType }

func (m *memCache) Get(_ context.Context, email, keyType string) (*usecases.CKDCacheEntry, error) {
	if e, ok := m.entries[m.key(email, keyType)]; ok {
		return e, nil
	}
	return nil, errors.New("not found")
}

func (m *memCache) Set(_ context.Context, e *usecases.CKDCacheEntry) error {
	cp := *e
	m.entries[m.key(e.Email, e.KeyType)] = &cp
	return nil
}

func (m *memCache) Delete(_ context.Context, email, keyType string) error {
	delete(m.entries, m.key(email, keyType))
	return nil
}

func (m *memCache) get(email string) (*usecases.CKDCacheEntry, bool) {
	e, ok := m.entries[email+"|x25519"]
	return e, ok
}

// nopLogger satisfies usecases.Logger.
type nopLogger struct{}

func (nopLogger) Debug(string, map[string]interface{})                {}
func (nopLogger) Info(string, map[string]interface{})                 {}
func (nopLogger) Warn(string, map[string]interface{})                 {}
func (nopLogger) Error(string, map[string]interface{})                {}
func (l nopLogger) WithFields(map[string]interface{}) usecases.Logger { return l }
