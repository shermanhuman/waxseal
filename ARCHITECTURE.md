# Architecture

waxseal keeps the plaintext of every Kubernetes secret in Google Secret
Manager (GSM) and only ciphertext in Git. Metadata under `.waxseal/` pins
each key of each SealedSecret to a GSM secret and a numeric version, so a
manifest can be re-encrypted at any time from what GSM holds.

## Packages

```
cmd/waxseal          os.Exit(cli.Main(...)) and nothing else
internal/
  version/     build identification (ldflags target)
  core/        domain types, validation, sentinel errors, enums, value generation   (leaf)
  computed/    {{var}} templates and the JSON payload stored in GSM for computed keys
  config/      .waxseal/config.yaml: strict parse, validate, defaults, marshal
  proc/        the one place a subprocess is started; ports hold a Runner for tests
  store/       Store interface, Google Secret Manager implementation, in-memory fake
  seal/        SealedSecret manifest type, kubeseal wrapper, certificate inspection, fake sealer
  kube/        kubectl wrapper
  gcp/         gcloud wrapper and the pure provisioning plan
  reminder/    expiry reminder providers (Google Tasks, Calendar) and fake
  repo/        the ONLY code that reads or writes files under the repository root
  ops/         use cases; never print, prompt, or read flags or the environment
  ui/          prompts, input resolution, output, colour, spinner
  cli/         cobra wiring: flags -> ui.Inputs -> ops -> ui.Result
  logging/     slog helpers; Redacted keeps secrets out of logs
```

Dependencies point downward only:
`core` ← {`computed`, `config`, `proc`, `store`, `seal`, `kube`, `gcp`, `reminder`} ← `repo` ← `ops` ← `cli`.
`ui` depends only on `core`. Only `ui` imports huh. Only `proc` starts
subprocesses. Only `repo` writes files. Only `cmd` calls `os.Exit`.
`golangci-lint` (forbidigo) and `scripts/dod.sh` enforce these.

## The three rules

1. **ops never talks to the user.** An operation takes everything it needs
   in an input struct and returns plain data. Missing values are
   `core.MissingInputError`s naming the flag; the CLI turns them into
   prompts on a terminal and into exit 2 otherwise.
2. **One prompt path.** `ui.Inputs` resolves every input the same way: a
   flag or argument that was set wins; otherwise a prompt on a terminal;
   otherwise the default; otherwise an error naming the flag. `--yes`
   answers confirmations and nothing else.
3. **One write path.** `repo` validates by re-parsing the exact bytes it is
   about to write, stages them to a temp file, fsyncs, then renames.

## The transaction

Every change to a secret goes through `ops.apply`:

1. Seal in memory. kubeseal and certificate problems surface before any
   write anywhere.
2. Dry run stops here and reports the planned changes.
3. Write GSM versions, remembering which secrets this call created.
4. `repo.Commit`: stage metadata and manifest, rename metadata first
   (it holds the pointer to the GSM version, which is unrecoverable),
   then the manifest (repairable with `reseal`).
5. On failure after 3: delete only the secrets this call created. A
   version added to a pre-existing secret is inert and is reported in an
   `UnrecordedVersionError`; re-running is safe.

Scope always comes from metadata, never from the manifest.

## On-disk formats

- `.waxseal/config.yaml` — see `internal/config`. Fields no command reads
  are still accepted and are dropped on the next write.
- `.waxseal/metadata/<shortName>.yaml` — `core.SecretMetadata`. Parsed
  strictly and written with `yaml.v3` in struct order, so rewriting a
  file changes at most quoting and param order. Comments do not survive a
  write.
- `keys/pub-cert.pem` — the controller certificate; must parse as one.
- SealedSecret manifests are written with `sigs.k8s.io/yaml` and carry the
  legacy scope annotations (`sealedsecrets.bitnami.com/namespace-wide:
  "true"`), which every controller version understands; both annotation
  forms are read.

Computed keys store a JSON payload in GSM (`computed.Payload`): the
template, its non-secret values and the `{{secret}}` part. `rotate` and
`key set` replace the secret part; `key edit --template/--param` replaces
the rest.

## Security invariants

- No plaintext on disk: results, changes and logs never carry values;
  `TestResults_NeverContainSecrets` checks the results.
- Numeric GSM versions only; aliases such as `latest` are rejected.
- Atomic, validated writes for everything waxseal owns.
- Encryption is delegated to the `kubeseal` binary so ciphertext matches
  the controller exactly.
- GCP authentication is Application Default Credentials; no tokens in the
  repo.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including `check` with warnings only) |
| 1 | runtime failure; `check` found errors; some secrets failed in `reseal`/`import` |
| 2 | usage: bad flag or argument, missing input, confirmation required, validation failure, `check --fail-on-warning` with warnings |
| 130 | cancelled: SIGINT or a declined prompt |

## Tests

- Unit tests per package against fakes (`store.FakeStore` with failure
  injection, `seal.FakeSealer`, `reminder.FakeProvider`, a scripted
  `ui.Prompter`), with a fixed clock.
- `internal/ops` is the regression net: every mutation, every failure
  point of the transaction, and byte-for-byte golden manifests.
- `internal/cli`: every command's `--help` is a golden; every command run
  with `--no-input` and no flags must succeed or exit 2 naming what is
  missing; every mutating command's `--dry-run -o json` is a golden.
- `tests/e2e` (build tag `e2e`): the CLI in-process against a real
  sealed-secrets controller in kind with real kubeseal. Runs on pushes to
  `main` and gates releases. `WAXSEAL_GSM_E2E=<project>` uses real Secret
  Manager.
- `docs/cli` is generated (`go run ./cmd/waxseal docs docs/cli`); CI
  fails when it is stale.
