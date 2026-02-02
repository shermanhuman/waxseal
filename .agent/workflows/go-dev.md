---
description: Go development workflow for waxseal CLI
---

# Go Development Workflow

## Build & Test

```bash
# Build
go build ./...

# Test
go test ./...

# After each substantive change, run both
```

## Architecture

waxseal core logic depends on small interfaces; keep Google/Kubernetes SDKs in thin adapters.

### Interfaces

- **Secret Store** (v1: GSM): `AccessVersion`, `AddVersion`, `CreateSecret`
- **Reminder Provider** (v1: Google Calendar): `Upsert`, `List`, `Delete`
- **Sealer**: seal and re-encrypt without external `kubeseal`

"Plugin" = compile-time implementations selected by config (no dynamic loading).

## Project Layout

```
cmd/waxseal/main.go     # Thin: flag wiring + cli.Execute() only
internal/
  cli/        # Cobra commands and output formatting
  core/       # Domain types + interfaces
  config/     # Config loading/validation
  k8s/        # kubectl/kubeconfig integration (optional)
  seal/       # kubeseal integration, cert fingerprinting
  files/      # Safe file walking + atomic writes
  store/      # Secret store implementations
  reminders/  # Reminder provider implementations
```

## Idioms

- Use `context.Context` for all I/O
- Return `error` as last value; wrap: `fmt.Errorf("context: %w", err)`
- **Never print secrets**
- Prefer small, testable helpers and table-driven tests

## Testing Strategy

### Unit Tests

- Config parsing/validation
- Manifest discovery + filtering
- YAML rewrite logic + atomic write behavior
- Command arg/flag parsing

### Golden Tests

- YAML transforms (input → expected output)

### Integration Tests

- `envtest` for Kubernetes API (fast, in-process)
- `kind` for E2E (nightly/release)

## Security

- Default mode: never write plaintext to disk
- Validate outputs before replacing files (`kind: SealedSecret`)
- "Print summary" features must be opt-in

## Cross-Platform

- Windows 11, macOS, Linux
- Deterministic output (stable ordering, idempotent reseal)
- For GCP provisioning: shell out to `gcloud` (assumed installed)
