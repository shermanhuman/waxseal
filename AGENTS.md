# WaxSeal Agent Guidelines

> Go CLI making SealedSecrets GitOps-friendly with GSM as source of truth.

## Tech Stack

- **Go**: 1.25.x
- **CLI**: github.com/spf13/cobra (skip Viper - use direct YAML parsing)
- **YAML**: sigs.k8s.io/yaml
- **Logging**: stdlib `log/slog`

## Commands

```bash
go build ./...   # Build
go test ./...    # Test
```

## Planning Documents

**Reference `.plan/` before implementing:**

| File                           | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `00-overview.md`               | System goals, operational model, hard requirements |
| `10-cli.md`                    | Command tree, targeting rules, interactivity       |
| `20-config.md`                 | `.waxseal/config.yaml` schema                      |
| `30-data-model.md`             | Metadata schema, computed keys, expirations        |
| `40-kubernetes-integration.md` | Controller discovery, cert handling, RBAC          |
| `50-reseal-and-rotate.md`      | Core algorithms                                    |
| `60-security.md`               | Security invariants                                |
| `70-testing-and-ci.md`         | Test strategy                                      |

## Project Structure

```
cmd/waxseal/main.go     # Thin entry point
internal/
  cli/                  # Cobra commands
  core/                 # Domain types + interfaces
  config/               # Config loading/validation
  files/                # Atomic writes, file walking
  seal/                 # kubeseal integration
  store/                # Secret store interface (GSM)
  reminders/            # Calendar integration
```

## Critical Rules

### Never Do

- Write plaintext secrets to disk
- Log secrets (including debug, errors, stack traces)
- Use GSM aliases (`latest`) - always pin numeric versions
- Depend on external `kubeseal` binary on PATH

### Always Do

- Use `context.Context` for all I/O
- Atomic file writes (temp → rename)
- Validate output before replacing files
- Return errors with context: `fmt.Errorf("context: %w", err)`

## File Formats

- **Repo config/metadata**: YAML (`.waxseal/config.yaml`, `.waxseal/metadata/*.yaml`)
- **GSM payloads**: JSON (operator hints)
- Fail closed on unknown fields
- See `.agent/workflows/formats.md` for details

## Workflows

- See `.agent/workflows/go-dev.md` for Go development guidelines
- See `.agent/workflows/formats.md` for format decisions
