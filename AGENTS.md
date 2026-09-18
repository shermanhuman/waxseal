# Working on waxseal

Read `ARCHITECTURE.md` first. The layering rules there are enforced by
lint and by `scripts/dod.sh`; a change that violates them will not pass CI.

## Commands

```sh
go build ./... && go vet ./... && go test ./...      # unit tests
golangci-lint run ./...                               # lint incl. layering rules
./scripts/dod.sh                                      # the grep-based rules
mkdir -p docs/cli && go run ./cmd/waxseal docs docs/cli   # regenerate the command reference
go test ./internal/cli -run 'TestHelpGolden|TestDryRunJSONGolden' -update   # accept surface changes (review the diff)
go test -tags e2e ./tests/e2e/                        # needs a kind cluster with sealed-secrets; see .github/workflows/e2e.yml
```

## Rules

- `internal/cli` contains no domain logic: it resolves inputs, calls
  `ops`, renders a `ui.Result`. New behaviour goes in `internal/ops` with
  a test against the fakes.
- `ops` never prints, prompts, reads flags or the environment, or
  branches on interactivity.
- All prompts and output go through `internal/ui`; all file writes
  through `internal/repo`; all subprocesses through `internal/proc`.
- Every command can be driven entirely by flags. An input without a
  default fails non-interactively with an error naming the flag. Secret
  values never come from argv.
- A new command needs a `--help` golden (the test tells you) and, if it
  mutates, a `--dry-run -o json` golden. Regenerate `docs/cli`.
- Never put a secret value in a result struct, a `Change`, a log line or
  an error message.
- Metadata and config are read and written through the same struct tags.
  Do not hand-build YAML.

## Releases

Versions are tagged with `go run ./scripts/release <major|minor|patch>`;
the tag triggers goreleaser after the e2e workflow passes. Breaking CLI
changes bump the minor version while below 1.0.
