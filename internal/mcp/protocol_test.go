package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// serve runs Serve over the given input lines and returns the decoded
// response lines.
func serve(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, "test"); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("output line is not one JSON object: %q (%v)", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func errCode(t *testing.T, m map[string]any) float64 {
	t.Helper()
	e, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("want a JSON-RPC error, got %v", m)
	}
	return e["code"].(float64)
}

// TestServeHandshakeAndRobustness covers S-8 and S-2: the MCP handshake works,
// notifications get no reply, and a bad line gets an error and does not end
// the session.
func TestServeHandshakeAndRobustness(t *testing.T) {
	resps := serve(t, &Server{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{not json`,
		`[1,2]`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"no/such/method"}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"decrypt_file","arguments":{}}}`,
	)
	if len(resps) != 8 {
		t.Fatalf("got %d responses, want 8 (no reply to the notification): %v", len(resps), resps)
	}

	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want the client's supported version", init["protocolVersion"])
	}
	if _, ok := init["capabilities"].(map[string]any)["tools"]; !ok {
		t.Errorf("initialize result has no tools capability: %v", init)
	}
	if init["serverInfo"].(map[string]any)["name"] == "" {
		t.Errorf("initialize result has no serverInfo name")
	}

	if c := errCode(t, resps[1]); c != -32700 {
		t.Errorf("bad JSON line: code %v, want -32700", c)
	}
	if c := errCode(t, resps[2]); c != -32600 {
		t.Errorf("array line: code %v, want -32600", c)
	}
	if _, ok := resps[3]["result"]; !ok || resps[3]["id"].(float64) != 2 {
		t.Errorf("ping: %v", resps[3])
	}
	tools := resps[4]["result"].(map[string]any)["tools"].([]any)
	for _, tool := range tools {
		if name := tool.(map[string]any)["name"]; name == "create_key" {
			t.Errorf("create_key is still advertised (S-3)")
		}
	}
	if c := errCode(t, resps[5]); c != -32601 {
		t.Errorf("unknown method: code %v, want -32601", c)
	}
	if c := errCode(t, resps[6]); c != -32602 {
		t.Errorf("unknown tool: code %v, want -32602", c)
	}
	call := resps[7]["result"].(map[string]any)
	if call["isError"] != true {
		t.Errorf("a failed tool call must be a result with isError true: %v", resps[7])
	}
}

// TestServeOversizedLine: a line over the size limit is answered with a parse
// error, and the next message is still served.
func TestServeOversizedLine(t *testing.T) {
	huge := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", maxMessageBytes) + `"}}`
	resps := serve(t, &Server{}, huge, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2", len(resps))
	}
	if c := errCode(t, resps[0]); c != -32700 {
		t.Errorf("oversized line: code %v, want -32700", c)
	}
	if resps[1]["id"].(float64) != 2 {
		t.Errorf("the message after an oversized line was not served: %v", resps[1])
	}
}

// TestToolResultIsJSON: a successful tool result is JSON text, not Go %v
// formatting.
func TestToolResultIsJSON(t *testing.T) {
	text, err := toolResultText(map[string]any{"keys": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("tool result text %q is not JSON: %v", text, err)
	}
}

// TestServeRejectsNullAndCompositeIDs covers T-5: "id": null is an invalid
// request, not a notification: it is answered with -32600 and NOT run.
// Object, boolean, and fractional ids (U-5) are refused the same way.
func TestServeRejectsNullAndCompositeIDs(t *testing.T) {
	resps := serve(t, &Server{},
		`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"list_keys","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`,
		`{"jsonrpc":"2.0","id":true,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"s","method":"ping"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)
	if len(resps) != 6 {
		t.Fatalf("got %d responses, want 6", len(resps))
	}
	if resps[5]["id"] != float64(7) {
		t.Errorf("integer id not echoed: %v", resps[5])
	}
	for i := 0; i < 4; i++ {
		if c := errCode(t, resps[i]); c != -32600 {
			t.Errorf("response %d: code %v, want -32600", i, c)
		}
	}
	if resps[4]["id"] != "s" {
		t.Errorf("string id not echoed: %v", resps[4])
	}
}

// TestDeleteKeyIsNotAnMCPTool covers T-4: key deletion is a CLI action.
func TestDeleteKeyIsNotAnMCPTool(t *testing.T) {
	for _, tool := range (&Server{}).ListTools() {
		if tool.Name == "delete_key" {
			t.Fatal("delete_key is still advertised")
		}
	}
	if _, err := (&Server{}).CallTool(context.Background(), "delete_key", map[string]interface{}{"key_id": "k"}); !errors.Is(err, errUnknownTool) {
		t.Fatalf("delete_key: err = %v, want unknown tool", err)
	}
}

// TestServeStopsOnCancel covers T-6: an idle server (no input arrives) returns
// promptly when its context is cancelled.
func TestServeStopsOnCancel(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close() //nolint:errcheck // test cleanup
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{}).Serve(ctx, pr, io.Discard, "test") }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop within 2 s of cancellation")
	}
}
