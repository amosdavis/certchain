// Package logging centralises slog-based structured logging for certchain.
//
// All certchain binaries should create exactly one root logger via New and
// propagate it to constructors; tests can use Discard to silence output.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the output format of the root handler.
type Format string

const (
	// FormatJSON emits line-delimited JSON records. Recommended for production
	// so log-aggregators (Cloud Logging, Loki, etc.) can parse structured fields.
	FormatJSON Format = "json"

	// FormatText emits the stdlib slog text format. Easier to read during
	// local development.
	FormatText Format = "text"
)

// Options configures the root logger. The zero value is valid and produces a
// FormatText logger at LevelInfo writing to stderr.
type Options struct {
	Format    Format
	Level     slog.Level
	Writer    io.Writer
	AddSource bool
}

// New builds a root *slog.Logger from Options.
func New(opts Options) *slog.Logger {
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}
	if opts.Format == "" {
		opts.Format = FormatText
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     opts.Level,
		AddSource: opts.AddSource,
	}

	var h slog.Handler
	switch strings.ToLower(string(opts.Format)) {
	case string(FormatJSON):
		h = slog.NewJSONHandler(opts.Writer, handlerOpts)
	default:
		h = slog.NewTextHandler(opts.Writer, handlerOpts)
	}
	return slog.New(h)
}

// ParseLevel parses a level name (debug|info|warn|error); unknown values
// return slog.LevelInfo. Case-insensitive.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseFormat parses a format name (json|text); unknown values return
// FormatText. Case-insensitive.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	default:
		return FormatText
	}
}

// Discard returns a logger that drops every record. Useful in tests.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
