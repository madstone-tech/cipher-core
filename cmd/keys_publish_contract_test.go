package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// conflictStub serves one publish response and captures the request body so
// the conflict-matrix tests can assert the rotation payload shape too.
type conflictStub struct {
	status int
	body   string
	reqBod []byte
	reqHD  http.Header
}

func newConflictStub(t *testing.T, status int, body string) (*conflictStub, *httptest.Server) {
	stub := &conflictStub{status: status, body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := ioAll(r)
		stub.reqBod, stub.reqHD = raw, r.Header.Clone()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	server := httptest.NewServer(mux)
	return stub, server
}

func ioAll(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }() //nolint:errcheck // best-effort: read-only close
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 256)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil //nolint:nilerr // EOF or any read end stops the copy
		}
	}
}

// rotateBody builds the rotation publish payload (fixture shape): token +
// fingerprint of the published key + poc fingerprint_token.
func rotateBody(fp string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"email":       "alice@example.com",
		"public_key":  "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"fingerprint": fp,
		"poc":         map[string]string{"type": "fingerprint_token"},
	})
	return string(b)
}

func withConflictServer(t *testing.T, status int, body string) (*conflictStub, *KeysCommand) {
	t.Helper()
	stub, server := newConflictStub(t, status, body)
	t.Setenv("CIPHER_SERVER_URL", server.URL)
	t.Cleanup(server.Close)
	db := seedX25519Key(t)
	return stub, &KeysCommand{dbPath: db}
}

// The four rows of the binding state machine from data-model.md, plus wrong
// fingerprint and invalid poc. Every row must relay distinctly and never
// retry (T009, FR-004; US2 acceptance 1-4).

func TestConflictStateMachineRows(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		body           string
		wantSentence   string // text the CLI must relay or show
		wantIsConflict bool
	}{
		{
			name:           "pinned token-only → current_fingerprint_required",
			status:         http.StatusConflict,
			body:           `{"error":"current_fingerprint_required","current_fingerprint":"ae216c2e"}`,
			wantSentence:   "ae216c2e",
			wantIsConflict: true,
		},
		{
			name:           "fingerprint mismatch",
			status:         http.StatusConflict,
			body:           `{"error":"fingerprint_mismatch"}`,
			wantSentence:   "fingerprint_mismatch",
			wantIsConflict: true,
		},
		{
			name:           "invalid possession proof",
			status:         http.StatusForbidden,
			body:           `{"error":"possession_proof_invalid"}`,
			wantSentence:   "possession_proof_invalid",
			wantIsConflict: false, // 403 → auth class (exit 2), not conflict
		},
		{
			name:           "rate limited",
			status:         http.StatusTooManyRequests,
			body:           `{"error":"rate_limited"}`,
			wantSentence:   "rate_limited",
			wantIsConflict: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub, cmd := withConflictServer(t, tc.status, tc.body)
			err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "tok")
			if err == nil {
				t.Fatalf("want error for %d", tc.status)
			}
			if !strings.Contains(err.Error(), tc.wantSentence) {
				t.Errorf("error must relay %q, got: %v", tc.wantSentence, err)
			}
			if tc.wantIsConflict && !errors.Is(err, entities.ErrKDConflict) {
				t.Errorf("status %d must map to the conflict class: %v", tc.status, err)
			}
			if tc.wantIsConflict && ExitCode(err) != ExitConflict {
				t.Errorf("exit code = %d, want %d", ExitCode(err), ExitConflict)
			}
			if !tc.wantIsConflict && tc.status == http.StatusForbidden && ExitCode(err) != ExitAuthFailed {
				t.Errorf("403 exit code = %d, want %d", ExitCode(err), ExitAuthFailed)
			}
			if stub.reqBod == nil {
				t.Error("stub saw no request")
			}
		})
	}
}

// TestConflictSurfacesCurrentFingerprint: the token-only conflict must show
// the server's current fingerprint so the user can build the rotation request
// (FR-004: "surface the server's current-fingerprint conflict with the
// returned fingerprint").
func TestConflictSurfacesCurrentFingerprint(t *testing.T) {
	_, cmd := withConflictServer(t, http.StatusConflict,
		`{"error":"current_fingerprint_required","current_fingerprint":"ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9"}`)

	err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "tok")
	if err == nil {
		t.Fatal("want conflict error")
	}
	if !strings.Contains(err.Error(),
		"ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9") {
		t.Errorf("error must surface the current fingerprint guidance: %v", err)
	}
}

// TestRotationPublishCarriesFingerprintAndPoc: a rotation-style publish (the
// current fingerprint + poc supplied) sends the additive fields verbatim.
func TestRotationPublishCarriesFingerprintAndPoc(t *testing.T) {
	stub, cmd := withConflictServer(t, http.StatusOK,
		`{"status":"published","email":"alice@example.com","email_hash":"ff8d…","rotated":true}`)

	// The full rotation path needs the stored key's fingerprint in the body —
	// PublishWithTokenAndFingerprint is the entry the CLI builds after a conflict.
	fp := "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9"
	if err := cmd.PublishWithTokenAndFingerprint(t.Context(), "alice@example.com", "", "tok", fp); err != nil {
		t.Fatalf("rotation publish: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(stub.reqBod, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["fingerprint"] != fp {
		t.Errorf("fingerprint field = %v, want %s", body["fingerprint"], fp)
	}
	poc, ok := body["poc"].(map[string]interface{})
	if !ok || poc["type"] != "fingerprint_token" {
		t.Errorf("poc field missing or wrong: %v", body["poc"])
	}
	if pk, ok := body["public_key"].(string); !ok || pk == "" {
		t.Errorf("public_key field must be present base64: %v", body["public_key"])
	}
}

// TestNoAutoRetryAfterConflict: a conflict must fail closed — exactly one
// request goes out, no silent retry with the returned fingerprint.
func TestNoAutoRetryAfterConflict(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"current_fingerprint_required","current_fingerprint":"ae216c2e"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	t.Setenv("CIPHER_SERVER_URL", server.URL)
	db := seedX25519Key(t)
	cmd := &KeysCommand{dbPath: db}

	_ = cmd.PublishWithToken(t.Context(), "alice@example.com", "", "tok")
	if hits != 1 {
		t.Errorf("requests sent = %d, want exactly 1 (no auto-retry)", hits)
	}
}

// TestConflictExitCodeConflict: the 409 path yields exit code 5.
func TestConflictExitCodeConflict(t *testing.T) {
	_, cmd := withConflictServer(t, http.StatusConflict, `{"error":"fingerprint_mismatch"}`)
	err := cmd.PublishWithToken(t.Context(), "alice@example.com", "", "tok")
	if ExitCode(err) != ExitConflict {
		t.Errorf("exit = %d, want %d", ExitCode(err), ExitConflict)
	}
	_ = os.Unsetenv("CIPHER_SERVER_URL")
}
