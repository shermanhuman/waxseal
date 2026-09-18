# Rewrite checklist

Working file for the ground-up rewrite. Deleted with `.plan/` in the docs phase.
The approved plan is the source of truth for architecture and command tree;
this file tracks gates, test obligations, and deliberate behaviour changes.

## Phase gates

- [ ] 0 Safety net: CI green on ubuntu + windows; v0.4.19 tagged
- [x] 1 `internal/repo`, marshal-based metadata/config, `core/enums.go`
- [x] 2 Ports: `proc`, `kube`, `gcp`, `seal.FetchCert`/`CertInfo`, `reminder.New`, `store.EnsureVersion` (the `template` -> `computed` rename and `Payload.Generator` -> `*core.GeneratorConfig` are deferred to the swap so the frozen CLI is not touched)
- [ ] 3 Read-only ops: `List`, `Show`, `Check`, `Discover`
- [ ] 5 `internal/ui`
- [ ] 6a `cli2` skeleton + help-golden walker + `--no-input` contract walker
- [ ] 4 Mutating ops (`apply` first, then `Reseal` dual-run against goldens)
- [ ] 6b Remaining commands + JSON goldens
- [ ] 7 Swap, dogfood, smoke e2e, `scripts/dod.sh` clean
- [ ] 8 Docs, `v0.5.0-rc.1`, `v0.5.0`

## Regression tests owed

Bugs 3-6 were hotfixed in the frozen `internal/cli` in Phase 0 but cannot be
tested there (package globals, hard-wired GSM store). Each needs an `ops`-level
test in Phase 4, written before the op it covers.

- [x] 1 Scope round-trip — `internal/seal`: `TestScope_RoundTrip`, `TestGetScope_AnnotationForms`
- [x] 2 Serializer drops `ref.shortName`, unquoted free text — `internal/files`: `TestSerializeMetadata_RoundTrip` (moves to `internal/repo`)
- [ ] 3 Metadata pointer written atomically and before the manifest — `ops`: fail the manifest write, assert metadata holds the new GSM version
- [ ] 4 Rollback runs on every later failure and never deletes pre-existing secrets — `ops`: `FakeStore.FailOn` after N creates; assert only newly created secrets are removed
- [ ] 5 A missing value is an error, never a silent skip — `ops.SetKeyValue` without a value returns `*MissingInputError`; `ops.Rotate` on a non-generated key returns a typed error
- [ ] 6 No result or log line contains a secret or rendered computed value — `ops`: marshal every result struct to JSON and assert the seeded secret is absent
- [x] 7 `reminders configure` updates a config that already has a reminders block — `internal/repo`: `TestWriteConfig_UpdatesRemindersInGeneratedConfig`

## Deliberate behaviour changes (decisions, not accidents)

- `state.yaml` is no longer written; existing files are left untouched.
- `rotate` acts on generated keys only; operator-supplied values go through `key set`.
- Scope comes from metadata, never re-derived from the manifest.
- A non-empty cross-secret `computed.inputs[].ref.shortName` is a validation error (it was silently resolved against the local secret).
- Well-known key-name catalogue and prefixed-key detection removed.
- Never-read config fields are accepted on read and dropped on write.
- Metadata files may be re-quoted on their next write; semantic content is unchanged.
- `reminders.auth` is no longer required (ADC was its only legal value). An unknown `reminders.provider` is now a validation error.
- Generated config and metadata files no longer carry explanatory comments, and comments in an existing config do not survive a write.
