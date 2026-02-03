# WaxSeal Agent Guidelines

> Go CLI making SealedSecrets GitOps-friendly with GSM as source of truth.

## Tech Stack

- **Go**: 1.25.x
- **CLI**: github.com/spf13/cobra (skip Viper - use direct YAML parsing)
- **YAML**: sigs.k8s.io/yaml
- **Logging**: stdlib `log/slog` with `Redacted` type
- **GCP**: cloud.google.com/go/secretmanager, google.golang.org/api/calendar

## Commands

```bash
go build ./...   # Build
go test ./...    # Test
go run ./cmd/waxseal --help  # Run from source
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
  cli/                  # Cobra commands, user interaction
  core/                 # Domain types (errors, metadata), no I/O
  config/               # Config loading/validation
  files/                # Atomic writes, YAML validators
  seal/                 # Sealer interface, SealedSecret parsing
  store/                # Store interface (GSM), FakeStore
  template/             # Computed key templates, cycle detection
  reseal/               # Orchestration engine
  reminders/            # Calendar provider interface
  logging/              # Redacted type, safe structured logging
testdata/
  infra-repo/           # Test fixture repo structure
```

## Package Responsibilities

| Package      | Responsibility                                             |
| ------------ | ---------------------------------------------------------- |
| `cli/`       | Cobra commands, user interaction, output formatting        |
| `core/`      | Domain types (SecretMetadata, errors), **no I/O**          |
| `config/`    | Config loading, validation, defaults                       |
| `files/`     | Atomic writes, YAML validators                             |
| `seal/`      | Sealer interface, hybrid encryption, SealedSecret parsing  |
| `store/`     | Store interface, FakeStore for testing, GSM implementation |
| `template/`  | Computed key templates, cycle detection                    |
| `reminders/` | Calendar provider interface, Google Calendar               |
| `reseal/`    | Orchestration (fetch → compute → seal → write)             |
| `logging/`   | Redacted type, safe structured logging                     |

## CLI Architecture

### Global Flags (Cobra Pattern)

The CLI uses package-level variables for global flags—a common Cobra pattern:

```go
// root.go
var (
    repoPath   string  // --repo flag
    configPath string  // --config flag
    dryRun     bool    // --dry-run flag
)
```

**Trade-off:** Simpler wiring vs. reduced testability. For larger CLIs, consider
dependency injection via a struct. The current approach is acceptable for waxseal's
scope and matches many production Cobra CLIs (kubectl, helm, etc.).

### Context in Commands

Always use `cmd.Context()` instead of `context.Background()`:

```go
func runFoo(cmd *cobra.Command, args []string) error {
    ctx := cmd.Context()  // ✓ Supports signal handling
    // NOT: ctx := context.Background()
}
```

### gRPC Error Handling (GSM)

Use gRPC status codes instead of string matching:

```go
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

if st, ok := status.FromError(err); ok {
    switch st.Code() {
    case codes.NotFound:
        return core.WrapNotFound(resource, err)
    case codes.PermissionDenied:
        return core.WrapPermissionDenied(resource, err)
    }
}
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

## Error Handling

**Sentinel errors** in `core/errors.go`:

- `ErrNotFound` - Resource not found
- `ErrPermissionDenied` - Access denied
- `ErrValidation` - Invalid input
- `ErrCycle` - Dependency cycle
- `ErrAlreadyExists` - Resource exists
- `ErrRetired` - Secret is retired

**Usage:**

```go
// Check sentinel
if errors.Is(err, core.ErrValidation) { ... }

// Wrap with context
return core.WrapNotFound("projects/x/secrets/foo", err)
return core.NewValidationError("version", "must be numeric")
```

## Testing Patterns

### Test Fakes

| Fake           | Location                | Purpose                  |
| -------------- | ----------------------- | ------------------------ |
| `FakeStore`    | `store/fake.go`         | In-memory GSM mock       |
| `FakeSealer`   | `seal/sealer.go`        | Deterministic encryption |
| `FakeProvider` | `reminders/calendar.go` | Mock calendar API        |

### Using FakeStore

```go
store := store.NewFakeStore()
store.SetVersion("projects/p/secrets/s", "1", []byte("value"))
data, _ := store.AccessVersion(ctx, "projects/p/secrets/s", "1")
```

### Using FakeSealer

```go
sealer := seal.NewFakeSealer()
encrypted, _ := sealer.Seal("name", "ns", "key", []byte("val"), "strict")
// Returns: "SEALED:ns/name/key=val"
```

### Test Fixtures

- `testdata/infra-repo/` - Complete repo structure
  - `.waxseal/config.yaml` - Sample config
  - `.waxseal/metadata/` - Sample metadata files
  - `apps/` - Sample SealedSecret manifests
  - `keys/pub-cert.pem` - Certificate placeholder

## File Formats

- **Repo config/metadata**: YAML (`.waxseal/config.yaml`, `.waxseal/metadata/*.yaml`)
- **GSM payloads**: JSON (operator hints)
- Fail closed on unknown fields
- See `.agent/workflows/formats.md` for details

## Workflows

- See `.agent/workflows/go-dev.md` for Go development guidelines
- See `.agent/workflows/formats.md` for format decisions

## Exit Codes

| Code | Meaning                                  |
| ---- | ---------------------------------------- |
| 0    | Success                                  |
| 1    | Partial failure (some operations failed) |
| 2    | Complete failure / validation error      |

## Security Logging

Never log secret values. Use the `Redacted` type:

```go
import "github.com/shermanhuman/waxseal/internal/logging"

secret := logging.Redacted("super-secret-value")
logging.Info("processing", "value", secret)
// Logs: "value=[REDACTED]"
```
