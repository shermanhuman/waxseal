---
trigger: always_on
---

# Go Development

## Error Handling

Sentinel errors in `core/errors.go`:

- `ErrNotFound` — Resource not found
- `ErrPermissionDenied` — Access denied
- `ErrValidation` — Invalid input
- `ErrCycle` — Dependency cycle
- `ErrAlreadyExists` — Resource exists
- `ErrRetired` — Secret is retired

Usage:

```go
// Check sentinel
if errors.Is(err, core.ErrValidation) { ... }

// Wrap with context
return core.WrapNotFound("projects/x/secrets/foo", err)
return core.NewValidationError("version", "must be numeric")
```

## Testing

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

- `testdata/infra-repo/` — Complete repo structure
  - `.waxseal/config.yaml` — Sample config
  - `.waxseal/metadata/` — Sample metadata files
  - `apps/` — Sample SealedSecret manifests
  - `keys/pub-cert.pem` — Certificate placeholder

## File Formats

- **Repo config/metadata**: YAML (`.waxseal/config.yaml`, `.waxseal/metadata/*.yaml`)
- **GSM payloads**: JSON (operator hints, template payloads)
- Fail closed on unknown fields
- Never accept `latest` (or any GSM alias) in metadata; numeric GSM version pins only

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
