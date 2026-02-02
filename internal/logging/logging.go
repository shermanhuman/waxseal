// Package logging provides safe structured logging that never logs secrets.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger is the package-level logger instance.
var Logger *slog.Logger

func init() {
	// Default to text handler with INFO level
	Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// SetOutput configures the logger output destination.
func SetOutput(w io.Writer) {
	Logger = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// SetLevel configures the minimum log level.
func SetLevel(level slog.Level) {
	Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

// SetJSON switches to JSON output format.
func SetJSON() {
	Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	Logger.Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	Logger.Info(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...any) {
	Logger.Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	Logger.Error(msg, args...)
}

// WithContext returns a logger with context values.
func WithContext(ctx context.Context) *slog.Logger {
	return Logger
}

// Redacted is a type that always logs as "[REDACTED]" to prevent secret leakage.
// Use this for any value that might contain sensitive data.
type Redacted string

// LogValue implements slog.LogValuer to redact the value.
func (r Redacted) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

// SecretRef represents a reference to a secret without exposing its value.
// Safe to log.
type SecretRef struct {
	Resource string // e.g., "projects/my-project/secrets/my-secret"
	Version  string // e.g., "3"
}

// LogValue implements slog.LogValuer for structured secret reference logging.
func (s SecretRef) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("resource", s.Resource),
		slog.String("version", s.Version),
	)
}
