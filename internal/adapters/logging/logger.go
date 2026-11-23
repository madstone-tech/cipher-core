package logging

import (
	"log/slog"
	"os"

	"github.com/madstone-tech/cipher-core/internal/core/usecases"
)

// SlogLogger implements the Logger interface using log/slog.
type SlogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger creates a structured logger that writes to stderr: stdout is
// the data channel of the CLI (--json output) and of the MCP server.
// format: "json" for production, "text" for CLI/dev.
// level: "debug", "info", "warn", "error".
func NewSlogLogger(level, format string) *SlogLogger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: slogLevel}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	l := slog.New(handler)
	// Set as default so package-level slog calls (e.g., in api/errors.go Internal())
	// use the same handler and level.
	slog.SetDefault(l)

	return &SlogLogger{
		logger: l,
	}
}

// NewSimpleLogger returns a text-format info-level logger for backward compatibility.
func NewSimpleLogger() *SlogLogger {
	return NewSlogLogger("info", "text")
}

func (l *SlogLogger) Debug(msg string, fields map[string]interface{}) {
	l.logger.Debug(msg, l.toArgs(fields)...)
}

func (l *SlogLogger) Info(msg string, fields map[string]interface{}) {
	l.logger.Info(msg, l.toArgs(fields)...)
}

func (l *SlogLogger) Warn(msg string, fields map[string]interface{}) {
	l.logger.Warn(msg, l.toArgs(fields)...)
}

func (l *SlogLogger) Error(msg string, fields map[string]interface{}) {
	l.logger.Error(msg, l.toArgs(fields)...)
}

func (l *SlogLogger) WithFields(fields map[string]interface{}) usecases.Logger {
	args := l.toArgs(fields)
	return &SlogLogger{
		logger: l.logger.With(args...),
	}
}

func (l *SlogLogger) toArgs(fields map[string]interface{}) []any {
	if len(fields) == 0 {
		return nil
	}
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return args
}
