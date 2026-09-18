# Rewrite checklist

Working file for the ground-up rewrite. Deleted with `.plan/` in the docs phase.
The approved plan is the source of truth for architecture and command tree;
this file tracks gates, test obligations, and deliberate behaviour changes.

## Phase gates

- [ ] 0 Safety net: CI green on ubuntu + windows; v0.4.19 tagged
- [x] 1 `internal/repo`, marshal-based metadata/config, `core/enums.go`
- [x] 2 Ports: `proc`, `kube`, `gcp`, `seal.FetchCert`/`CertInfo`, `reminder.New`, `store.EnsureVersion` (the `template` -> `computed` rename and `Payload.Generator` -> `*core.GeneratorConfig` are deferred to the swap so the frozen CLI is not touched)
- [x] 3 Read-only ops: `List`, `Show`, `Check`, `Discover`
- [x] 5 `internal/ui`
- [x] 6a `cli2` skeleton + help-golden walker + `--no-input` contract walker
- [x] 4 Mutating ops (`apply` first, then `Reseal` dual-run against goldens)
- [x] 6b Remaining commands + JSON goldens
- [x] 7 Swap, smoke e2e written, `scripts/dod.sh` clean (dogfood against the real gcloud env still to run)
- [ ] 8 Docs, `v0.5.0-rc.1`, `v0.5.0`

## Regression tests owed

Bugs 3-6 were hotfixed in the frozen `internal/cli` in Phase 0 but cannot be
tested there (package globals, hard-wired GSM store). Each needs an `ops`-level
test in Phase 4, written before the op it covers.

- [x] 1 Scope round-trip — `internal/seal`: `TestScope_RoundTrip`, `TestGetScope_AnnotationForms`
- [x] 2 Serializer drops `ref.shortName`, unquoted free text — `internal/files`: `TestSerializeMetadata_RoundTrip` (moves to `internal/repo`)
- [x] 3 Metadata pointer written atomically and before the manifest — `repo`: `TestCommit_MetadataLandsBeforeManifest`; `ops`: `TestSetKeyValue_MetadataPointerSurvivesManifestFailure`, `TestApply_UnrecordedVersionIsReported`
- [x] 4 Rollback runs on every later failure and never deletes pre-existing secrets — `ops`: `TestApply_RollbackDeletesOnlyWhatItCreated`, `TestApply_GSMFailureRollsBackEarlierCreates`, `TestApply_SealFailureWritesNothing`
- [x] 5 A missing value is an error, never a silent skip — `ops`: `TestSetKeyValue_PlainAndComputed` (empty value), `TestRotate` (`ErrNotGenerated`)
- [x] 6 No result or log line contains a secret or rendered computed value — `ops`: `TestResults_NeverContainSecrets`
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
- `discover` is read-only: it lists manifests and whether metadata covers them. Registering happens in `import`, which reads the cluster secret and pushes to GSM, so metadata never carries a placeholder GSM version (the old stub wrote `version: "1"`).
- `check metadata` no longer warns about internal hostnames in `computed.params`; it would fire on nearly every GitOps repo and guards nothing. It now does check that manifest scope and key set agree with metadata.
- The `testdata/infra-repo` fixture had a truncated certificate and an invalid reminders provider (`google-calendar`); both fixed.
- `tests/integration` folded into `ops`/`repo`/`seal` tests and deleted. `TestComputedKeyCycleDetection` has no equivalent: computed keys are evaluated in metadata order and may only reference keys already evaluated, so a cycle is impossible by construction (a forward reference is an "unknown key" validation error).
- `import` registers every key as `external`; connection strings become computed keys with the password as `{{secret}}`. Re-importing a registered secret pushes new versions for the keys the cluster still has and reports the ones it dropped.
