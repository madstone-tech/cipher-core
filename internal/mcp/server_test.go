package mcp

import (
	"context"
	"testing"
)

// TestSharingToolsRemoved guards against re-advertising the share_key /
// revoke_share MCP tools. Sharing wrote policies/grants to the single-user
// SQLite store with no delivery channel, so the tools were removed. ListTools
// is stateless, so a zero-value Server is sufficient.
func TestSharingToolsRemoved(t *testing.T) {
	s := &Server{}

	for _, tool := range s.ListTools() {
		if tool.Name == "share_key" || tool.Name == "revoke_share" {
			t.Errorf("removed tool %q is still advertised by ListTools", tool.Name)
		}
	}

	for _, name := range []string{"share_key", "revoke_share"} {
		if _, err := s.CallTool(context.Background(), name, nil); err == nil {
			t.Errorf("CallTool(%q) should return an unknown-tool error after removal", name)
		}
	}
}

// TestExpectedToolsPresent pins the surviving MCP tool set so an accidental
// removal of a working tool is caught.
func TestExpectedToolsPresent(t *testing.T) {
	want := []string{
		"encrypt_file", "decrypt_file", "list_keys",
		"export_key", "get_status", "lookup_key", "import_key",
	}

	got := make(map[string]bool)
	for _, tool := range (&Server{}).ListTools() {
		got[tool.Name] = true
	}

	for _, name := range want {
		if !got[name] {
			t.Errorf("expected MCP tool %q is missing from ListTools", name)
		}
	}
	if n := len((&Server{}).ListTools()); n != len(want) {
		t.Errorf("ListTools returned %d tools, want %d", n, len(want))
	}
}
