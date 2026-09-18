package seal

import (
	"context"
	"fmt"
	"strings"

	"github.com/shermanhuman/waxseal/internal/proc"
)

// KubesealSealer delegates to the kubeseal binary for encryption.
// This ensures compatibility with the sealed secrets controller.
type KubesealSealer struct {
	certPath string
	run      proc.Runner
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

	run := s.run
	if run == nil {
		run = proc.Run
	}
	out, err := run(context.Background(), value, "kubeseal", args...)
	if err != nil {
		return "", fmt.Errorf("seal %s: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Kubeseal exposes the kubeseal binary's cluster operations. The zero value
// is usable.
type Kubeseal struct {
	run proc.Runner
}

// FetchCert asks the controller for its current sealing certificate.
func (k Kubeseal) FetchCert(ctx context.Context, controllerNamespace, controllerName string) ([]byte, error) {
	run := k.run
	if run == nil {
		run = proc.Run
	}
	out, err := run(ctx, nil, "kubeseal", "--fetch-cert",
		"--controller-namespace="+controllerNamespace,
		"--controller-name="+controllerName)
	if err != nil {
		return nil, fmt.Errorf("fetch certificate: %w", err)
	}
	if _, err := ParseCert(out); err != nil {
		return nil, fmt.Errorf("fetch certificate: controller returned %w", err)
	}
	return out, nil
}

// Compile-time check
var _ Sealer = (*KubesealSealer)(nil)
