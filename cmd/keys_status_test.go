package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// statusStub serves GET /api/v1/ckd/status with a fixed response and records
// what it saw: the fingerprint query parameter and the Authorization header.
type statusStub struct {
	gotQuery string
	gotAuth  string
}

// newStatusStub serves status with the given response and hands back the
// recorder. authHeader must be non-nil for the stub to record the header.
func newStatusStub(t *testing.T, status int, body string) (stub *statusStub, server *httptest.Server) {
	t.Helper()
	stub = &statusStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/status", func(w http.ResponseWriter, r *http.Request) {
		stub.gotQuery = r.URL.Query().Get("fingerprint")
		stub.gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	return stub, httptest.NewServer(mux)
}

const fullFP = "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9"

func TestStatusReportsPublishedState(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantOut string
	}{
		{"published", `{"published":true,"fingerprint":"` + fullFP + `","email_hash":"ff8d"}`, "✓ Published"},
		{"not published (tombstoned or never published)", `{"published":false,"fingerprint":"` + fullFP + `"}`, "Not published"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub, server := newStatusStub(t, http.StatusOK, tc.body)
			t.Setenv("CIPHER_SERVER_URL", server.URL)

			cmd := &KeysCommand{dbPath: t.TempDir() + "/absent.db"}
			out := captureStdout(t, func() {
				// Upper-case input: the CLI normalizes before the request.
				if err := cmd.Status(t.Context(), "", "tok", strings.ToUpper(fullFP)); err != nil {
					t.Errorf("status: %v", err)
				}
			})
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("output %q should contain %q", out, tc.wantOut)
			}
			if stub.gotQuery != fullFP {
				t.Errorf("query fingerprint = %q, want lowercased %q", stub.gotQuery, fullFP)
			}
			if stub.gotAuth != "Bearer tok" {
				t.Errorf("Authorization = %q, want Bearer tok", stub.gotAuth)
			}
		})
	}
}

func TestStatusInvalidFingerprintRejectedBeforeRequest(t *testing.T) {
	stub, server := newStatusStub(t, http.StatusOK, `{"published":true}`)
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: t.TempDir() + "/absent.db"}
	err := cmd.Status(t.Context(), "", "tok", "not-hex")
	if err == nil {
		t.Fatal("want error for a non-hex fingerprint")
	}
	if !strings.Contains(err.Error(), "64 hex") {
		t.Errorf("error should name the shape: %v", err)
	}
	if stub.gotQuery != "" {
		t.Error("no request must reach the server for an invalid fingerprint")
	}
}

func TestStatusAbsentTokenFailsBeforeRequest(t *testing.T) {
	stub, server := newStatusStub(t, http.StatusOK, `{"published":true}`)
	t.Setenv("CIPHER_SERVER_URL", server.URL)
	t.Setenv("KD_TOKEN", "")
	os.Unsetenv("KD_TOKEN") //nolint:errcheck // best-effort: test env cleanup

	cmd := &KeysCommand{dbPath: t.TempDir() + "/absent.db"}
	err := cmd.Status(t.Context(), "", "", fullFP)
	if err == nil {
		t.Fatal("want token error before any request")
	}
	if !strings.Contains(err.Error(), "KD_TOKEN") {
		t.Errorf("error should name the token sources: %v", err)
	}
	if stub.gotQuery != "" {
		t.Error("no request must be sent when the token is absent")
	}
}

func TestStatusAuthFailureRelayedWithExitCode(t *testing.T) {
	_, server := newStatusStub(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: t.TempDir() + "/absent.db"}
	err := cmd.Status(t.Context(), "", "bad", fullFP)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should carry the relay: %v", err)
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("error should relay the server body: %v", err)
	}
	if ExitCode(err) != ExitAuthFailed {
		t.Errorf("exit = %d, want %d", ExitCode(err), ExitAuthFailed)
	}
}

func TestStatusRateLimitedMapsToGenericError(t *testing.T) {
	_, server := newStatusStub(t, http.StatusTooManyRequests, `{"error":"rate_limited"}`)
	t.Setenv("CIPHER_SERVER_URL", server.URL)

	cmd := &KeysCommand{dbPath: t.TempDir() + "/absent.db"}
	err := cmd.Status(t.Context(), "", "tok", fullFP)
	if err == nil {
		t.Fatal("want error")
	}
	if ExitCode(err) != ExitError {
		t.Errorf("429 exit = %d, want %d", ExitCode(err), ExitError)
	}
}

// captureStdout redirects fmt.Print output for one function call.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = old
	buf := make([]byte, 4096)
	n, rerr := r.Read(buf)
	if rerr != nil && n == 0 {
		t.Logf("no stdout output captured")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return string(buf[:n])
}
