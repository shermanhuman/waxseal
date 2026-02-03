#!/bin/bash
# Docker entrypoint for E2E tests
# Runs inside the runner container, connects to DinD
set -e

CLUSTER_NAME="waxseal-e2e"

log() { echo -e "\033[0;32m[E2E]\033[0m $1"; }
error() { echo -e "\033[0;31m[E2E]\033[0m $1"; }

# Wait for Docker to be available
log "Waiting for Docker..."
until docker info &>/dev/null; do
    sleep 1
done
log "✓ Docker available"

# Create kind cluster
log "Creating kind cluster: $CLUSTER_NAME"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log "Cluster already exists, reusing..."
else
    kind create cluster \
        --name "$CLUSTER_NAME" \
        --config /workspace/tests/e2e/kind-config.yaml \
        --wait 120s
fi
log "✓ Cluster ready"

# Export kubeconfig and fix the server address
kind export kubeconfig --name "$CLUSTER_NAME"

# Fix the server address - kind uses 0.0.0.0 but we need host.docker.internal or the container IP
# Get the control plane container IP
CONTROL_PLANE_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CLUSTER_NAME}-control-plane" 2>/dev/null || echo "")
if [ -n "$CONTROL_PLANE_IP" ]; then
    log "Fixing kubeconfig to use control plane IP: $CONTROL_PLANE_IP"
    sed -i "s|https://0.0.0.0:|https://${CONTROL_PLANE_IP}:|g" ~/.kube/config
    sed -i "s|https://127.0.0.1:|https://${CONTROL_PLANE_IP}:|g" ~/.kube/config
fi

# Install Sealed Secrets
log "Installing Sealed Secrets controller..."
if kubectl get deployment -n kube-system sealed-secrets-controller &>/dev/null; then
    log "Sealed Secrets already installed"
else
    helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets 2>/dev/null || true
    helm repo update

    helm install sealed-secrets sealed-secrets/sealed-secrets \
        --namespace kube-system \
        --set fullnameOverride=sealed-secrets-controller \
        --wait \
        --timeout 120s
fi
log "✓ Sealed Secrets installed"

# Wait for controller
log "Waiting for controller to be ready..."
kubectl wait --for=condition=available deployment/sealed-secrets-controller \
    -n kube-system --timeout=60s
log "✓ Controller ready"

# Create test namespace
kubectl create namespace waxseal-test 2>/dev/null || true

# Build waxseal
log "Building waxseal..."
cd /workspace
go build -o /tmp/waxseal ./cmd/waxseal
export PATH="/tmp:$PATH"
log "✓ waxseal built"

# Run tests
log "Running E2E tests..."
go test -v ./tests/e2e/... -timeout 10m

log "✓ E2E tests completed!"

# Cleanup (optional - keep cluster for debugging)
if [ -z "$KEEP_CLUSTER" ]; then
    log "Cleaning up cluster..."
    kind delete cluster --name "$CLUSTER_NAME"
    log "✓ Cluster deleted"
else
    log "Keeping cluster (KEEP_CLUSTER is set)"
fi
