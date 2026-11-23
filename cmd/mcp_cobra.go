package cmd

import (
	"github.com/spf13/cobra"
)

// mcpCmd represents the mcp command
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for AI assistants",
	Long: `Start the Model Context Protocol (MCP) server.

The MCP server provides 7 tools for AI assistants:
- encrypt_file: Encrypt a file to <file>.mdstn (never replaces a file)
- decrypt_file: Decrypt a .mdstn file next to it (never replaces a file)
- list_keys: List all keys
- export_key: Return the public part of a key (writes no file)
- get_status: Get Cipher status
- lookup_key: Look up a public key by email via CKD
- import_key: Import a public key from base64

Keys are created and deleted with "mdstn-cipher keys create" and
"mdstn-cipher keys delete", not through MCP: the 24-word recovery phrase
must not go into an AI transcript, and a prompt injection must not be able
to destroy keys.

The server speaks MCP over stdio (JSON-RPC 2.0, one message per line;
protocol versions 2025-06-18 and 2024-11-05). Only protocol
messages are written to stdout; logs go to stderr.`,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, args []string) error {
	ctx, stop := commandContext(cmd)
	defer stop()
	mcpCommand := NewMCPCommand(dbPath)
	return mcpCommand.Execute(ctx)
}
