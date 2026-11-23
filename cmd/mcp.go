package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/madstone-tech/cipher-core/internal/mcp"
)

type MCPCommand struct {
	dbPath string
}

func NewMCPCommand(dbPath string) *MCPCommand {
	return &MCPCommand{
		dbPath: dbPath,
	}
}

func (c *MCPCommand) Execute(ctx context.Context) error {
	server, err := mcp.NewServer(c.dbPath)
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}
	// stdout is the protocol channel: only Serve writes to it. A signal
	// (SIGTERM, SIGINT) ends the session normally.
	if err := server.Serve(ctx, os.Stdin, os.Stdout, version); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
