---
trigger: always_on
---

# Security Rules

## Never Do

- Write plaintext secrets to disk
- Log secrets (including debug, errors, stack traces)
- Use GSM aliases (`latest`) — always pin numeric versions

## Always Do

- Use `context.Context` for all I/O
- Atomic file writes (temp → rename)
- Validate output before replacing files
- Return errors with context: `fmt.Errorf("context: %w", err)`
- Use `kubeseal` binary for encryption (via `KubesealSealer`) — guarantees controller compatibility
