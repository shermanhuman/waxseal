package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactedNeverLogsValue(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)

	secret := Redacted("super-secret-value-12345")
	Info("processing secret", "value", secret)

	output := buf.String()

	// Must contain [REDACTED]
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got: %s", output)
	}

	// Must NOT contain the actual secret
	if strings.Contains(output, "super-secret-value-12345") {
		t.Errorf("secret value leaked in logs: %s", output)
	}
}

func TestSecretRefLogsReference(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)

	ref := SecretRef{
		Resource: "projects/my-project/secrets/db-password",
		Version:  "5",
	}
	Info("accessing secret", "ref", ref)

	output := buf.String()

	// Should contain the resource name (safe to log)
	if !strings.Contains(output, "db-password") {
		t.Errorf("expected resource name in output, got: %s", output)
	}

	// Should contain version
	if !strings.Contains(output, "5") {
		t.Errorf("expected version in output, got: %s", output)
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Temporarily swap logger
	oldLogger := Logger
	Logger = logger
	defer func() { Logger = oldLogger }()

	Info("this should not appear")
	Warn("this should appear")

	output := buf.String()

	if strings.Contains(output, "this should not appear") {
		t.Error("INFO message should be filtered at WARN level")
	}

	if !strings.Contains(output, "this should appear") {
		t.Error("WARN message should appear")
	}
}
