package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishStub serves the publish/unpublish endpoints with a script of
// responses. Each path records the requests it saw (headers included) so the
// tests can assert on the Authorization header and pre-flight failures.
type publishStub struct {
	t          *testing.T
	status     map[string]int
	body       map[string]string
	publishReq *http.Request
	publishBod []byte
	unpubReq   *http.Request
}

func newPublishStub(t *testing.T, status int, body string) (*publishStub, *httptest.Server) {
	stub := &publishStub{
		t:      t,
		status: map[string]int{"/api/v1/ckd/publish": status, "/api/v1/ckd/unpublish": status},
		body:   map[string]string{"/api/v1/ckd/publish": body, "/api/v1/ckd/unpublish": body},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		stub.publishReq, stub.publishBod = r, raw
		w.WriteHeader(stub.status["/api/v1/ckd/publish"])
		_, _ = w.Write([]byte(stub.body["/api/v1/ckd/publish"]))
	})
	mux.HandleFunc("/api/v1/ckd/unpublish", func(w http.ResponseWriter, r *http.Request) {
		stub.unpubReq = r
		w.WriteHeader(stub.status["/api/v1/ckd/unpublish"])
		_, _ = w.Write([]byte(stub.body["/api/v1/ckd/unpublish"]))
	})
	return stub, httptest.NewServer(mux)
}

func TestPublishAbsentTokenFailsBeforeRequest(t *testing.T) {
	stub, server := newPublishStub(t, http.StatusOK, `{"status":"published"}`)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	// Clear any ambient token sources the shell may hold.
	os.Unsetenv("KD_TOKEN")
	if err := os.Unsetenv("KD_TOKEN"); err != nil {
		t.Fatalf("unset KD_TOKEN: %v", err)
	}

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "")
	if err == nil {
		t.Fatal("publish without token: want error, got nil")
	}
	if !strings.Contains(err.Error(), "KD_TOKEN") {
		t.Errorf("error should name the token sources, got: %v", err)
	}
	if stub.publishReq != nil {
		t.Error("no request must be sent when the token is absent")
	}

	err = cmd.UnpublishWithToken(t.Context(), "alice@example.com", "", "")
	if err == nil {
		t.Fatal("unpublish without token: want error, got nil")
	}
	if stub.unpubReq != nil {
		t.Error("no request must be sent when the token is absent")
	}
}

// seedX25519Key creates a real key store at dir/cipher.db holding one default
// X25519 key, so publish tests exercise the real selection path.
func seedX25519Key(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "cipher.db")
	cmd := NewKeysCommand(db, false, false)
	if err := cmd.Create(context.Background(), "x25519", "", "", "", "kp", true); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	return db
}

func TestPublishSendsBearerHeader(t *testing.T) {
	stub, server := newPublishStub(t, http.StatusOK, `{"status":"published","email":"a@b.c","email_hash":"ff"}`)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	if err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "tok-123"); err != nil {
		t.Fatalf("publish with token: %v", err)
	}
	if stub.publishReq == nil {
		t.Fatal("stub saw no publish request")
	}
	if got := stub.publishReq.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", got)
	}
}

func TestUnpublishSendsBearerHeader(t *testing.T) {
	stub, server := newPublishStub(t, http.StatusOK, `{"status":"unpublished"}`)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	if err := cmd.UnpublishWithToken(t.Context(), "alice@example.com", "", "tok-123"); err != nil {
		t.Fatalf("unpublish with token: %v", err)
	}
	if got := stub.unpubReq.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", got)
	}
}

func TestPublishInvalidTokenRelaysAuthFailure(t *testing.T) {
	_, server := newPublishStub(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "bad-token")
	if err == nil {
		t.Fatal("publish with invalid token: want error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should carry the 401 relay, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("error should relay the server body, got: %v", err)
	}
}

func TestFlagTokenWinsOverEnv(t *testing.T) {
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"status":"published"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)
	t.Setenv("KD_TOKEN", "env-token")

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	if err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "flag-token"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(seen) != 1 || seen[0] != "Bearer flag-token" {
		t.Errorf("flag token must win over env: saw %v", seen)
	}
}

func TestEnvTokenUsedWhenNoFlag(t *testing.T) {
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"status":"published"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)
	t.Setenv("KD_TOKEN", "env-token")
	t.Cleanup(func() { _ = os.Unsetenv("KD_TOKEN") })

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	if err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", ""); err != nil {
		t.Fatalf("publish via env token: %v", err)
	}
	if len(seen) != 1 || seen[0] != "Bearer env-token" {
		t.Errorf("env token should be the fallback: saw %v", seen)
	}
}

func TestPublishRequestBodyShape(t *testing.T) {
	stub, server := newPublishStub(t, http.StatusOK, `{"status":"published"}`)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: seedX25519Key(t)}
	if err := cmd.PublishWithToken(t.Context(), "  ALICE@Example.COM  ", "", "tok"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if stub.publishReq == nil {
		t.Fatal("stub saw no publish request")
	}
	var body map[string]string
	if err := json.Unmarshal(stub.publishBod, &body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if body["email"] != "  ALICE@Example.COM  " {
		t.Errorf("email must be relayed as the user typed it: %q", body["email"])
	}
	if body["public_key"] == "" {
		t.Error("public_key field must be present (base64)")
	}
}
