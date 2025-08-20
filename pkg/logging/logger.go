package logging

import (
	"log/slog"
	"os"
	"strings"
)

// NewLoggerFromEnv creates a logger using environment variables
// SLICE_LOG_LEVEL: debug|info|warn|error (default: info)
// SLICE_LOG_FORMAT: text|json (default: text)
func NewLoggerFromEnv() *slog.Logger {
	level := slog.LevelInfo
	format := "text"
	
	if levelStr := os.Getenv("SLICE_LOG_LEVEL"); levelStr != "" {
		level = parseLogLevel(levelStr)
	}
	
	if formatStr := os.Getenv("SLICE_LOG_FORMAT"); formatStr != "" {
		format = strings.ToLower(formatStr)
	}
	
	opts := &slog.HandlerOptions{
		Level: level,
	}
	
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	
	return slog.New(handler)
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}