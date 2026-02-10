---
trigger: always_on
---

# Stack & Architecture

## Tech Stack

- **Go**: 1.25.x
- **CLI**: github.com/spf13/cobra (skip Viper — use direct YAML parsing)
- **YAML**: sigs.k8s.io/yaml
- **Logging**: stdlib `log/slog` with `Redacted` type
- **GCP**: cloud.google.com/go/secretmanager, google.golang.org/api/calendar

## Commands

```bash
go build ./...                # Build
go test ./...                 # Test
go run ./cmd/waxseal --help   # Run from source
go install ./cmd/waxseal      # Install to $GOPATH/bin
waxseal --version             # Check version
```

### Production Build (with version info)

```bash
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

go build -ldflags "-X github.com/shermanhuman/waxseal/internal/cli.Version=$VERSION \
                   -X github.com/shermanhuman/waxseal/internal/cli.Commit=$COMMIT \
                   -X github.com/shermanhuman/waxseal/internal/cli.BuildDate=$BUILD_DATE" \
  -o waxseal ./cmd/waxseal
```

## Planning Documents

Reference `.plan/` before implementing:

| File                           | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `00-overview.md`               | System goals, operational model, hard requirements |
| `10-cli.md`                    | Command tree, targeting rules, interactivity       |
| `20-config.md`                 | `.waxseal/config.yaml` schema                      |
| `30-data-model.md`             | Metadata schema, computed keys, expirations        |
| `40-kubernetes-integration.md` | Controller discovery, cert handling, RBAC           |
| `50-reseal-and-rotate.md`      | Core algorithms                                    |
| `60-security.md`               | Security invariants                                |
| `70-testing-and-ci.md`         | Test strategy                                      |

## Project Structure

```
cmd/waxseal/main.go     # Thin entry point
internal/
  cli/                  # Cobra commands, user interaction
    root.go             # Root command, global flags, command groups, version
    grouping.go         # GroupIDs and Hidden flags (help layout)
    resolve.go          # Shared CLI plumbing (resolveConfig, resolveStore, etc.)
    style.go            # Output formatting, ANSI helpers, text utilities
    keys.go             # Shared key helpers (ParseKeySpec, PromptGeneratorKind, etc.)
    check.go            # 'check' parent + cert/expiry/metadata/gsm/cluster subcommands
    meta.go             # 'meta' parent + list secrets/keys, showkey
    rotate.go           # 'rotate' command + serializeMetadata
    edit.go             # 'edit' wizard (TUI secret/action picker)
    add.go              # 'addkey' (hidden, advanced)
    update.go           # 'updatekey' (hidden, advanced)
    retire.go           # 'retirekey' (hidden, advanced)
    gcp_bootstrap.go    # 'gsm' parent + gcp-bootstrap, bootstrap
  core/                 # Domain types (errors, metadata, generate), no I/O
  config/               # Config loading/validation
  files/                # Atomic writes, YAML validators, metadata I/O helpers
  gcp/                  # Pure GCP shell wrappers (gcloud, billing, orgs)
  seal/                 # Sealer interface, SealedSecret parsing/building
  store/                # Store interface (GSM), FakeStore, ID formatting
  template/             # Computed key templates, cycle detection, pattern detection
  reseal/               # Orchestration engine
  reminder/             # Calendar provider interface
  state/                # CLI state persistence
  logging/              # Redacted type, safe structured logging
testdata/
  infra-repo/           # Test fixture repo structure
```

## CLI Command Tree

Primary commands (shown in `waxseal --help`):

```
waxseal
├── edit            # Key Management — interactive add/update/retire wizard
│   ├── addkey      #   Jump to add-key flow
│   ├── updatekey   #   Jump to update-key flow
│   └── retirekey   #   Jump to retire-key flow
├── rotate          # Key Management — rotate secret values
├── reseal          # Operations — reseal all from GSM (default = all)
├── check           # Operations — health checks
│   ├── cert        # Certificate expiry
│   ├── expiry      # Secret expiration
│   ├── metadata    # Config/schema/hygiene
│   ├── gsm         # Verify GSM versions exist
│   └── cluster     # Compare metadata vs live cluster
├── meta            # Metadata viewers
│   ├── list
│   │   ├── secrets # List all registered secrets
│   │   └── keys    # List keys within a secret
│   └── showkey     # Detailed metadata for one secret
├── setup           # Installation — interactive wizard
└── advanced        # Prints hidden command reference
```

Advanced commands (shown via `waxseal advanced`):

```
waxseal
├── addkey          # Non-interactive secret creation
├── updatekey       # Non-interactive key update
├── retirekey       # Mark a key as retired
├── discover        # Scan repo for SealedSecret manifests
├── gsm
│   ├── bootstrap       # Push cluster secrets → GSM metadata
│   └── gcp-bootstrap   # Initialize GCP infrastructure
└── reminders
    ├── sync / list / clear / setup
```

## Package Responsibilities

| Package     | Responsibility                                                           |
| ----------- | ------------------------------------------------------------------------ |
| `cli/`      | Cobra commands, user interaction, output formatting                      |
| `core/`     | Domain types (SecretMetadata, errors, generate), **no I/O**              |
| `config/`   | Config loading, validation, defaults                                     |
| `files/`    | Atomic writes, YAML validators, metadata I/O helpers                     |
| `gcp/`      | Pure GCP shell wrappers (gcloud, billing, orgs) — no CLI dependency      |
| `seal/`     | KubesealSealer (uses kubeseal binary), CertSealer, SealedSecret builder  |
| `store/`    | Store interface, FakeStore, GSM impl, `SanitizeGSMName`/`FormatSecretID` |
| `template/` | Computed key templates, cycle detection, connection string detection      |
| `reminder/` | Calendar provider interface, Google Calendar                             |
| `reseal/`   | Orchestration (fetch → compute → seal → write)                           |
| `state/`    | CLI state persistence (atomic writes via `files.AtomicWriter`)           |
| `logging/`  | Redacted type, safe structured logging                                   |

## CLI Architecture

### Global Flags (Cobra Pattern)

The CLI uses package-level variables for global flags — a common Cobra pattern:

```go
// root.go
var (
    repoPath   string  // --repo flag
    configPath string  // --config flag
    dryRun     bool    // --dry-run flag
)
```

### Context in Commands

Always use `cmd.Context()` instead of `context.Background()`:

```go
func runFoo(cmd *cobra.Command, args []string) error {
    ctx := cmd.Context()  // ✓ Supports signal handling
}
```

### gRPC Error Handling (GSM)

Use gRPC status codes instead of string matching:

```go
if st, ok := status.FromError(err); ok {
    switch st.Code() {
    case codes.NotFound:
        return core.WrapNotFound(resource, err)
    case codes.PermissionDenied:
        return core.WrapPermissionDenied(resource, err)
    }
}
```
