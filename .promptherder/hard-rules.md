---
trigger: always_on
---

# Hard Rules

Project-level rules that are always active. Added by `/rule` or manually.

- **Releases: default to patch.** Use `go run ./scripts/release patch` (default), `minor` (breaking changes), or `major` (ask first). The script bumps `internal/cli/root.go`, commits, and tags — push triggers goreleaser on CI (`git push origin main && git push origin v<version>`). Bump patch for every fix, feature, or improvement. Bump minor only for breaking changes (renamed/removed CLI flags, changed config schema, altered command behavior users must adapt to). Do not bump major without explicit approval — major is reserved for a stability milestone (v1.0.0). The release script enforces these checks: tests must pass, working tree must be clean.

- **Document all CLI flags and commands.** When adding or changing command-line arguments, update both `README.md` (Commands table and relevant sections) and the Cobra command help text (`--help`). Hidden/advanced commands go in `waxseal advanced` output.
