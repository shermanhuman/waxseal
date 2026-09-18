// Package kube talks to the cluster through kubectl.
package kube

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/shermanhuman/waxseal/internal/core"
	"github.com/shermanhuman/waxseal/internal/proc"
)

// Client runs kubectl against the current context. The zero value is usable.
type Client struct {
	run proc.Runner
}

func (c Client) runner() proc.Runner {
	if c.run == nil {
		return proc.Run
	}
	return c.run
}

// GetSecret returns the decoded data of a Secret. A missing secret is an
// error wrapping core.ErrNotFound.
func (c Client) GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	out, err := c.runner()(ctx, nil, "kubectl", "get", "secret", name, "-n", namespace, "-o", "json")
	if err != nil {
		var exitErr *proc.ExitError
		if errors.As(err, &exitErr) && strings.Contains(exitErr.Stderr, "NotFound") {
			return nil, core.WrapNotFound(fmt.Sprintf("secret %s/%s", namespace, name), err)
		}
		return nil, err
	}
	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &secret); err != nil {
		return nil, fmt.Errorf("parse secret %s/%s: %w", namespace, name, err)
	}
	data := make(map[string][]byte, len(secret.Data))
	for key, encoded := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode %s/%s key %s: %w", namespace, name, key, err)
		}
		data[key] = decoded
	}
	return data, nil
}

// FindController locates the sealed-secrets controller by its standard Helm
// label and returns its namespace and service name. It returns an error
// wrapping core.ErrNotFound when no controller is running.
func (c Client) FindController(ctx context.Context) (namespace, service string, err error) {
	run := c.runner()
	out, err := run(ctx, nil, "kubectl", "get", "pods", "-A",
		"-l", "app.kubernetes.io/name=sealed-secrets",
		"-o", "jsonpath={.items[0].metadata.namespace}")
	namespace = strings.TrimSpace(string(out))
	if err != nil || namespace == "" {
		return "", "", core.WrapNotFound("sealed-secrets controller", err)
	}
	for _, candidate := range []string{"sealed-secrets-controller", "sealed-secrets"} {
		if _, err := run(ctx, nil, "kubectl", "get", "svc", "-n", namespace, candidate); err == nil {
			return namespace, candidate, nil
		}
	}
	return "", "", core.WrapNotFound("sealed-secrets controller service in "+namespace, nil)
}

// ListNamespaces returns the cluster's namespaces.
func (c Client) ListNamespaces(ctx context.Context) ([]string, error) {
	out, err := c.runner()(ctx, nil, "kubectl", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}
