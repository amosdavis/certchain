package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"unknown": slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"err":     slog.LevelError,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	if got := ParseFormat("json"); got != FormatJSON {
		t.Errorf("ParseFormat(json) = %v, want %v", got, FormatJSON)
	}
	if got := ParseFormat("text"); got != FormatText {
		t.Errorf("ParseFormat(text) = %v, want %v", got, FormatText)
	}
	if got := ParseFormat(""); got != FormatText {
		t.Errorf("ParseFormat(empty) = %v, want %v", got, FormatText)
	}
}

func TestNewJSONWritesStructuredRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Format: FormatJSON, Level: slog.LevelInfo, Writer: &buf})
	logger.Info("hello", "key", "value")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("record is not valid json: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", rec["msg"])
	}
	if rec["key"] != "value" {
		t.Errorf("key = %v, want value", rec["key"])
	}
}

func TestNewRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Level: slog.LevelWarn, Writer: &buf})
	logger.Info("should-not-appear")
	logger.Warn("should-appear")
	if strings.Contains(buf.String(), "should-not-appear") {
		t.Errorf("info record leaked through warn threshold: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "should-appear") {
		t.Errorf("warn record was dropped: %s", buf.String())
	}
}

func TestDiscardDoesNotPanic(t *testing.T) {
	l := Discard()
	l.Info("noop")
	l.Error("noop", "k", 1)
}
