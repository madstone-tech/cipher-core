package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/madstone-tech/cipher-core/internal/core/entities"
)

// TestMalformedToolCallsReturnErrors covers R-5: a missing or non-string
// argument must give an error, not a panic that stops the MCP process.
func TestMalformedToolCallsReturnErrors(t *testing.T) {
	s := &Server{}
	cases := map[string]map[string]interface{}{
		"encrypt_file {}":           {},
		"encrypt_file nil":          nil,
		"decrypt_file {}":           {},
		"decrypt_file file_path=42": {"file_path": 42},
		"export_key {}":             {},
		"lookup_key {}":             {},
		"import_key {}":             {},
	}
	tools := map[string]string{
		"encrypt_file {}": "encrypt_file", "encrypt_file nil": "encrypt_file",
		"decrypt_file {}": "decrypt_file", "decrypt_file file_path=42": "decrypt_file",
		"export_key {}": "export_key",
		"lookup_key {}": "lookup_key", "import_key {}": "import_key",
	}
	for name, args := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: CallTool panicked: %v", name, r)
				}
			}()
			_, err := s.CallTool(context.Background(), tools[name], args)
			if !errors.Is(err, entities.ErrInvalidInput) {
				t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
			}
		}()
	}
}

// TestCallToolRecoversFromPanics: any other panic inside a tool handler
// becomes an error, so one bad call never ends the session.
func TestCallToolRecoversFromPanics(t *testing.T) {
	s := &Server{} // nil dependencies: a valid call reaches a nil pointer
	_, err := s.CallTool(context.Background(), "list_keys", map[string]interface{}{})
	if err == nil {
		t.Fatal("list_keys on a Server without a key store succeeded")
	}
}
