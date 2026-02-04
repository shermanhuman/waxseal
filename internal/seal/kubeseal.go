package seal

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// KubesealSealer delegates to the kubeseal binary for encryption.
// This ensures compatibility with the sealed secrets controller.
type KubesealSealer struct {
	certPath string
}

// NewKubesealSealer creates a sealer that uses the kubeseal binary.
func NewKubesealSealer(certPath string) *KubesealSealer {
	return &KubesealSealer{certPath: certPath}
}

// Seal uses the kubeseal binary to encrypt a value.
func (s *KubesealSealer) Seal(name, namespace, key string, value []byte, scope string) (string, error) {
	// Map scope to kubeseal flag format
	var scopeFlag string
	switch scope {
	case ScopeNamespaceWide:
		scopeFlag = "namespace-wide"
	case ScopeClusterWide:
		scopeFlag = "cluster-wide"
	default:
		scopeFlag = "strict"
	}

	// Build kubeseal command
	args := []string{
		"--raw",
		"--cert", s.certPath,
		"--scope", scopeFlag,
		"--namespace", namespace,
	}

	// For strict scope, name is also required
	if scopeFlag == "strict" {
		args = append(args, "--name", name)
	}

	cmd := exec.Command("kubeseal", args...)
	cmd.Stdin = bytes.NewReader(value)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kubeseal: %w: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// GetCertFingerprint returns a placeholder since we don't parse the cert.
func (s *KubesealSealer) GetCertFingerprint() string {
	return "kubeseal-binary"
}

// Compile-time check
var _ Sealer = (*KubesealSealer)(nil)
