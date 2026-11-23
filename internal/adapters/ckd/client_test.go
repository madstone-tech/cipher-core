package ckd_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/adapters/ckd"
)

// TestFetchKey_Base64DecodesBytesCorrectly verifies that fetchKey correctly
// base64-decodes the public_key field instead of treating it as raw bytes.
func TestFetchKey_Base64DecodesBytesCorrectly(t *testing.T) {
	// Create a 32-byte X25519 public key
	originalKey := make([]byte, 32)
	for i := range originalKey {
		originalKey[i] = byte(i + 1)
	}
	encodedKey := base64.StdEncoding.EncodeToString(originalKey)

	// Set up a mock CKD server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"email":       "test@example.com",
			"public_key":  encodedKey,
			"fingerprint": "sha256:abc123",
			"created_at":  1234567890,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer ts.Close()

	client := ckd.NewClientWithBaseURL(ts.URL)
	key, err := client.LookupKeyFromURL(context.Background(), ts.URL+"/.well-known/mdstn-cipher/abc", "test@example.com")
	if err != nil {
		t.Fatalf("LookupKey failed: %v", err)
	}

	// The returned key bytes should match the DECODED original bytes,
	// NOT the base64 ASCII string bytes.
	if len(key.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32 (decoded bytes, not ASCII base64 string)", len(key.PublicKey))
	}

	for i, b := range key.PublicKey {
		if b != originalKey[i] {
			t.Errorf("PublicKey[%d] = %d, want %d", i, b, originalKey[i])
		}
	}
}

// TestFetchKey_InvalidBase64ReturnsError verifies that malformed base64 data
// results in an error rather than silently returning garbage bytes.
func TestFetchKey_InvalidBase64ReturnsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"email":       "test@example.com",
			"public_key":  "not-valid-base64!!!",
			"fingerprint": "sha256:abc123",
			"created_at":  1234567890,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer ts.Close()

	client := ckd.NewClientWithBaseURL(ts.URL)
	_, err := client.LookupKeyFromURL(context.Background(), ts.URL+"/.well-known/mdstn-cipher/abc", "test@example.com")
	if err == nil {
		t.Error("expected error for invalid base64 public key, got nil")
	}
}
