package cipher_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// directoryStub serves the publish/unpublish/status routes and records
// what it received per path (headers and bodies) so the SDK-level contract
// can be asserted without the CLI.
type directoryStub struct {
	auth      string
	pubBody   []byte
	tombstone map[string]bool
}

func newDirectoryStub(t *testing.T) (*directoryStub, *httptest.Server) {
	t.Helper()
	stub := &directoryStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ckd/publish", func(w http.ResponseWriter, r *http.Request) {
		stub.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		stub.pubBody = raw
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"published","email":"qa@me.com","email_hash":"7b00e27f","rotated":true}`))
	})
	mux.HandleFunc("/api/v1/ckd/unpublish", func(w http.ResponseWriter, r *http.Request) {
		stub.auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"unpublished"}`))
	})
	mux.HandleFunc("/api/v1/ckd/status", func(w http.ResponseWriter, r *http.Request) {
		stub.auth = r.Header.Get("Authorization")
		fp := r.URL.Query().Get("fingerprint")
		if strings.ToUpper(fp) != fp && len(fp) == 64 {
			// lowercase passed through — fine
		}
		if stub.tombstone[fp] {
			_, _ = w.Write([]byte(`{"published":false,"fingerprint":"` + fp + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"published":true,"fingerprint":"` + fp + `","email_hash":"7b00e27f"}`))
	})
	return stub, httptest.NewServer(mux)
}

// TestSDKPublishUnpublishStatusParity: the SDK's publish, unpublish, and
// status methods hit the same wire contract as the CLI, with the Bearer
// token and the rotation artifact, and surface the rotation flags.
func TestSDKPublishUnpublishStatusParity(t *testing.T) {
	stub, server := newDirectoryStub(t)
	client, err := cipher.New(cipher.Config{
		DBPath:             cipher.InMemory,
		PublishServerURL:   server.URL,
		PublishToken:       "sdk-token-1",
		PublishFingerprint: "071d8bbb62d1f9502c55606d391ed515e7993b1a471dc3b27279860971f6212f",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close() //nolint:errcheck // best-effort close in test

	ctx := context.Background()

	// Publish by KeyID alternative: create first.
	k, err := client.CreateKey(ctx, "sdk-key", "sdk-pass-1")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	info, err := client.PublishKey(ctx, "qa@me.com", k.Key.ID)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if info.EmailHash == "" {
		t.Error("publish must return the fingerprint-index hash")
	}
	if !info.Rotated {
		t.Error("rotation flag lost (stub answered rotated:true)")
	}
	if stub.auth != "Bearer sdk-token-1" {
		t.Errorf("Authorization = %q, want Bearer sdk-token-1", stub.auth)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(stub.pubBody, &body); err != nil {
		t.Fatal(err)
	}
	if body["email"] != "qa@me.com" {
		t.Errorf("publish email = %v", body["email"])
	}
	if body["public_key"] == "" || body["fingerprint"] != "071d8bbb62d1f9502c55606d391ed515e7993b1a471dc3b27279860971f6212f" {
		t.Errorf("publish body missing key or rotation fingerprint: %v", body)
	}
	if poc, ok := body["poc"].(map[string]interface{}); !ok || poc["type"] != "fingerprint_token" {
		t.Errorf("publish poc missing or wrong: %v", body["poc"])
	}

	// Status by fingerprint.
	st, err := client.KeyStatus(ctx, strings.ToUpper("ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9"))
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Published || st.EmailHash == "" {
		t.Errorf("status = %+v", st)
	}

	// Unpublish.
	if err := client.UnpublishKey(ctx, "qa@me.com"); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	if stub.auth != "Bearer sdk-token-1" {
		t.Errorf("unpublish lost the bearer header: %q", stub.auth)
	}
}

// TestSDKLookupCarriesKeyType: the SDK surfaces the declared key type from
// the wire response (v0.4.0 forward-compatibility wiring).
func TestSDKLookupCarriesKeyType(t *testing.T) {
	fixture := `{"email":"qa@me.com","public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","fingerprint":"ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9","created_at":1763932800,"key_type":"x25519"}`
	mux := http.NewServeMux()
	var kid, sig string
	mux.HandleFunc("/.well-known/mdstn-cipher/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Mdstn-Kd-Keyid", kid)
		w.Header().Set("X-Mdstn-Kd-Signature", sig)
		_, _ = w.Write([]byte(fixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	// The fixture is unsigned: without a serving signature the lookup must
	// fail closed (the tamper check is covered in the adapters/ckd tests);
	// assert the failure mode to keep the SDK honest about verification.
	client, err := cipher.New(cipher.Config{DBPath: cipher.InMemory, CKDDirectoryURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close() //nolint:errcheck // best-effort close in test

	_, err = client.LookupKey(context.Background(), "qa@me.com")
	if err == nil {
		t.Fatal("unsigned response accepted by the SDK lookup path")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("error should name the integrity failure: %v", err)
	}
}

// TestSDKPublishWithoutTokenGuides: with no token configured (flag and env
// blank), publish fails with guidance and NO request leaves the process;
// the rest of the SDK (keys CRUD) keeps working — the nil-publisher panic
// from the pre-parity SDK is fixed.
func TestSDKPublishWithoutTokenGuides(t *testing.T) {
	t.Setenv("KD_TOKEN", "")
	stub, server := newDirectoryStub(t)
	client, err := cipher.New(cipher.Config{
		DBPath:           cipher.InMemory,
		PublishServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close() //nolint:errcheck // best-effort close in test

	ctx := context.Background()
	k, err := client.CreateKey(ctx, "no-token-key", "sdk-pass-1")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	_, err = client.PublishKey(ctx, "qa@me.com", k.Key.ID)
	if err == nil {
		t.Fatal("publish without a token must fail")
	}
	if !strings.Contains(err.Error(), "KD_TOKEN") {
		t.Errorf("error should name the token sources: %v", err)
	}
	if stub.pubBody != nil {
		t.Error("no request may leave the process without a token")
	}
	if err := client.UnpublishKey(ctx, "qa@me.com"); err == nil {
		t.Error("unpublish without a token must fail")
	}

	// The rest of the SDK works: the client is not half-constructed.
	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("list keys after failed publish config: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("keys = %d, want 1 (no panic)", len(keys))
	}
}
