---
description: Go development guidelines for waxseal (public CLI)
---

# Go Development Guidelines (waxseal)

## Stack

- Go: 1.25.x
- CLI: github.com/spf13/cobra (and optionally github.com/spf13/viper for config)
- Logging: stdlib `log/slog`
- YAML: sigs.k8s.io/yaml

See `.agents/Formats.md` for the YAML vs JSON policy.

## Goals

- Cross-platform native CLI (Windows 11, macOS, Linux)
- Deterministic output (stable ordering, idempotent reseal)
- Safe writes (atomic, never leave partial/garbage YAML)
- Never log secrets
- Keep dependencies minimal and pinned

## Formats

- Repo config/metadata: YAML (`.waxseal/config.yaml`, `.waxseal/metadata/*.yaml`).
- GSM payloads (operator hints): JSON.

Implementation expectations:

- Fail closed on unknown fields in config/metadata.
- Keep serialization deterministic (stable ordering, minimal diffs).

## Architecture (separation of concerns)

waxseal core logic depends on small interfaces and keeps Google/Kubernetes SDKs in thin adapters.

- Secret Store interface (v1: GSM): access pinned version, add version, optionally create secret.
- Reminder Provider interface (v1: Google Calendar): upsert/list/clean reminder events.
  - Auth (v1): Application Default Credentials only.
- Sealing interface: seal and re-encrypt without depending on an arbitrary `kubeseal` on PATH.

"Plugin" means compile-time implementations selected by config (no dynamic loading).

## Project Structure

- Keep `cmd/waxseal/main.go` thin: flag wiring + `cli.Execute()` only.
- Put core logic in `internal/`.

Suggested layout:

- cmd/
  - waxseal/
    - main.go
- internal/
  - cli/        cobra commands and output formatting
  - core/       domain types + interfaces
  - config/     config loading/validation
  - k8s/        kubectl/kubeconfig integration (optional)
  - seal/       kubeseal integration, cert fingerprinting
  - files/      safe file walking + atomic writes

## Idioms

- Use `context.Context` for all I/O.
- Return `error` as last return value; wrap with `fmt.Errorf("context: %w", err)`.
- Don’t print secrets. Ever.
- Prefer small, testable helpers and table-driven tests.

## Testing

- Unit tests for:
  - config parsing/validation
  - manifest discovery + filtering
  - YAML rewrite logic + atomic write behavior
  - command arg/flag parsing
- Golden tests for YAML transforms.

## Security

- Default mode must not write plaintext values to disk.
- If a “print summary” feature exists, keep it opt-in and obvious.
- Validate outputs before replacing files (e.g., contains `kind: SealedSecret`).

## Commands

- Build: `go build ./...`
- Test: `go test ./...`

## Workflow

- After each substantive change:
  - `go build ./...`
  - `go test ./...`
