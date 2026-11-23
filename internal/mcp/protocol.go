package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// maxMessageBytes bounds one JSON-RPC message (one line on stdio). A longer
// line is answered with a parse error and skipped.
const maxMessageBytes = 4 << 20

// supportedProtocolVersions are the MCP protocol versions this server speaks,
// newest first. initialize answers with the client's version when it is in
// this list, else with the newest. 2025-03-26 is not listed: it requires
// JSON-RPC batch support, which this server does not have (T-5).
var supportedProtocolVersions = []string{"2025-06-18", "2024-11-05"}

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// errUnknownTool is returned by CallTool for a tool name it does not know.
var errUnknownTool = errors.New("unknown tool")

var errLineTooLong = errors.New("message is longer than the limit")

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve runs the MCP stdio transport: one JSON-RPC message per line from r,
// one response per line to w. Only protocol messages are written to w. A bad
// line is answered with an error and the session goes on. Serve returns nil
// at the end of r, and an error only when w fails or ctx ends.
//
// Reading runs in its own goroutine, so a cancelled ctx (SIGTERM, SIGINT)
// stops an idle server at once, without waiting for the next line (T-6).
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer, version string) error {
	type msg struct {
		line []byte
		err  error
	}
	lines := make(chan msg)
	go func() {
		in := bufio.NewReaderSize(r, 64<<10)
		for {
			line, err := readLine(in)
			select {
			case lines <- msg{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil && !errors.Is(err, errLineTooLong) {
				return
			}
		}
	}()
	enc := json.NewEncoder(w)
	for {
		var m msg
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m = <-lines:
		}
		line, err := m.line, m.err
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		var resp *rpcResponse
		switch {
		case errors.Is(err, errLineTooLong):
			resp = errorResponse(nil, codeParseError, fmt.Sprintf("message longer than %d bytes", maxMessageBytes))
		case err != nil && !errors.Is(err, io.EOF):
			return fmt.Errorf("read MCP message: %w", err)
		default:
			resp = s.handleLine(ctx, line, version)
		}
		if resp != nil {
			if err := enc.Encode(resp); err != nil {
				return fmt.Errorf("write MCP response: %w", err)
			}
		}
	}
}

// readLine returns the next line without its newline. If the line is longer
// than maxMessageBytes, the rest of it is read and dropped, and the error is
// errLineTooLong.
func readLine(in *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := in.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxMessageBytes+1 {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return nil, errLineTooLong
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}

// handleLine answers one message. It returns nil for a notification (a
// request without an id) and for an empty line: JSON-RPC forbids a reply.
func (s *Server) handleLine(ctx context.Context, line []byte, version string) *rpcResponse {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	if !json.Valid(line) {
		return errorResponse(nil, codeParseError, "invalid JSON")
	}
	if line[0] != '{' {
		return errorResponse(nil, codeInvalidRequest, "a message must be one JSON object (batches are not supported)")
	}
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		return errorResponse(req.ID, codeInvalidRequest, "invalid JSON-RPC 2.0 request")
	}
	// A request id must be a string or a number; "id": null is invalid (it is
	// not a notification), so it is refused and NOT run (T-5).
	if len(req.ID) > 0 && !validID(req.ID) {
		return errorResponse(nil, codeInvalidRequest, "id must be a string or an integer")
	}
	notification := len(req.ID) == 0

	var result any
	var rerr *rpcError
	switch req.Method {
	case "initialize":
		result = initializeResult(req.Params, version)
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": s.ListTools()}
	case "tools/call":
		result, rerr = s.handleToolCall(ctx, req.Params)
	default:
		if notification {
			return nil // notifications/initialized, notifications/cancelled, …
		}
		rerr = &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}
	if notification {
		return nil
	}
	if rerr != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func initializeResult(params json.RawMessage, version string) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	chosen := supportedProtocolVersions[0]
	if err := json.Unmarshal(params, &p); err == nil && slices.Contains(supportedProtocolVersions, p.ProtocolVersion) {
		chosen = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": chosen,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "mdstn-cipher", "version": version},
	}
}

// handleToolCall runs one tool. A failed tool is a normal result with
// isError true (MCP), so the host can show the error to the model. An unknown
// tool or malformed params is a JSON-RPC error.
func (s *Server) handleToolCall(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil || params.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "tools/call needs params.name"}
	}
	out, err := s.CallTool(ctx, params.Name, params.Arguments)
	if errors.Is(err, errUnknownTool) {
		return nil, &rpcError{Code: codeInvalidParams, Message: err.Error()}
	}
	if err != nil {
		return toolContent(err.Error(), true), nil
	}
	text, err := toolResultText(out)
	if err != nil {
		return toolContent("internal error: "+err.Error(), true), nil
	}
	return toolContent(text, false), nil
}

// toolResultText encodes a tool result as JSON text.
func toolResultText(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode tool result: %w", err)
	}
	return string(b), nil
}

func toolContent(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func errorResponse(id json.RawMessage, code int, msg string) *rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// validID reports whether a JSON-RPC id is a string or an integer (MCP
// does not allow a fractional id such as 1.5, U-5).
func validID(id json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return false
	}
	switch v.(type) {
	case string:
		return true
	case float64:
		return !bytes.ContainsAny(id, ".eE")
	}
	return false
}
