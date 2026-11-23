package cipher

import (
	"context"

	"github.com/madstone-tech/cipher-core/internal/adapters/crypto"
	"github.com/madstone-tech/cipher-core/internal/adapters/logging"
	mcpserver "github.com/madstone-tech/cipher-core/internal/mcp"
	cipherports "github.com/madstone-tech/cipher-core/pkg/cipherports"
)

// Tool mirrors the MCP tool descriptor (internal/mcp.Tool) — exported so
// hosts can inspect ListTools results without importing internal packages.
type Tool = mcpserver.Tool

// MCPServer is the embedded-server surface: the two entry points an MCP host
// (or a cross-implementation test) needs. Implemented by the internal MCP server.
type MCPServer interface {
	ListTools() []Tool
	CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error)
}

// Constructors for the core adapter implementations, exposed for consumers
// that WIRE the ports themselves (hosts implementing
// cipherports.IdentityKeyRepository with their own storage).
//
// Consuming applications build the crypto/session engines via these
// constructors rather than importing the internal adapter package directly.

// NewCryptoEngine returns the default CryptoEngine implementation.
func NewCryptoEngine() cipherports.CryptoEngine { return crypto.NewEngine() }

// NewArgon2idKEKProvider returns the Argon2id KEK provider.
func NewArgon2idKEKProvider() cipherports.KEKProvider { return crypto.NewArgon2idKEKProvider() }

// NewInMemorySessionStore returns the in-memory KEK session store.
// The context governs the store's janitor goroutine lifetime.
func NewInMemorySessionStore(ctx context.Context) cipherports.SessionStore {
	return crypto.NewInMemorySessionStore(ctx)
}

// NewSimpleLogger returns the default structured logger. It writes to stderr.
func NewSimpleLogger() cipherports.Logger { return logging.NewSimpleLogger() }

// NewSlogLogger returns a level/format-configured slog-backed logger that
// writes to stderr (level: "debug"|"info"|"warn"|"error"; format: "json"|"text").
func NewSlogLogger(level, format string) cipherports.Logger {
	return logging.NewSlogLogger(level, format)
}

// NewMCPServer returns the MCP server (7 tools: no key creation or deletion, and no tool
// writes to a caller-chosen path) bound to a SQLite database path. Exposed
// for hosts that EMBED the tools (and for cross-implementation tests). The
// interface gives the tools only (ListTools, CallTool); the stdio transport
// (initialize, notifications, line framing) is `mdstn-cipher mcp`.
//
// The concrete server's session store additionally implements Stop()
// (background pruner) — hosts that need to stop it assert the optional
// interface{ Stop() } locally.
func NewMCPServer(dbPath string) (MCPServer, error) {
	return mcpserver.NewServer(dbPath)
}

// NewMCPServerViaSDK is NewMCPServer under a consumer-facing alias.
func NewMCPServerViaSDK(dbPath string) (MCPServer, error) { return NewMCPServer(dbPath) }

// NewFileEncoder returns the .mdstn format codec (EncodeHeader family).
func NewFileEncoder() cipherports.FileEncoder { return crypto.NewFileEncoder() }
