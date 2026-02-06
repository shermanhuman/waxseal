# Refactor Plan — CLI Simplification + DRY Consolidation + Package Reorganization

> Created 2026-02-06. Tracking branch: `refactor`.

Three interlocking workstreams:
- **(A)** Simplify the CLI surface — remove unnecessary flags, merge commands
- **(B)** Extract shared helpers — eliminate DRY violations
- **(C)** Reorganize packages — move domain logic out of `cli/`

Steps are ordered so each builds on the last: package moves first, then helpers,
then CLI surgery.

---

## Phase 1 — Package Reorganization

### Step 1: Extract `internal/gcp/`

Move infrastructure helpers out of `cli/gcp_bootstrap.go` into a new
`internal/gcp/` package. These are pure shell wrappers with no CLI dependency:

- `checkGcloudInstalled`
- `checkKubesealInstalled`
- `ensureADC`
- `checkGcloudAccount`
- `runGcloudCommand` / `runGcloudJSON`
- `listBillingAccounts`
- `listProjects`
- `listOrganizations`

Update imports in `gcp_bootstrap.go` and `setup.go`.

### Step 2: Move `sanitizeGSMName` → `store/` and add `FormatGSMResource`

`sanitizeGSMName` in `bootstrap.go` is used across 5 CLI files. Move to
`store/store.go` as `SanitizeGSMName`. Add:

```go
func FormatGSMResource(projectID, secretName string) string {
    return fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName)
}
```

Replaces 6 inline `fmt.Sprintf` calls.

### Step 3: Move template detection to `template/`

Move `detectConnectionStringTemplate` and `analyzeKeyForTemplate` from
`discover.go` to `template/template.go`. These are template pattern detection
logic, not CLI concerns.

### Step 4: Rename `reminders/` → `reminder/`

Go convention is singular package names. Update the one import site
(`cli/reminders.go`).

---

## Phase 2 — Core Helpers & DRY Extraction

### Step 5: Add metadata I/O helpers to `core/`

Add to `core/metadata.go`:

```go
func LoadMetadataFile(repoPath, shortName string) (*SecretMetadata, error)
func LoadAllMetadata(repoPath string) ([]*SecretMetadata, error)
```

Replaces:
- 7× shortName-load pattern (rotate, update, retire, show, bootstrap, reseal/engine)
- 7× directory-iteration pattern (list, validate, reencrypt, reminders, bootstrap,
  reseal/engine)

### Step 6: Create `cli/resolve.go` — shared CLI plumbing

Extract into one file:

| Helper | Replaces |
|--------|----------|
| `resolveConfigPath() string` | 10× `filepath.Join` boilerplate |
| `loadConfig() (*config.Config, error)` | Wraps resolveConfigPath + config.Load |
| `newStore(ctx, cfg) (store.Store, func(), error)` | 5× GSM store creation |
| `newSealer(cfg) seal.Sealer` | 4× cert path + KubesealSealer |
| `recordState(repoPath, fn func(*state.State))` | 4× load/mutate/save pattern |

### Step 7: Unify value generation into `core/generate.go`

Three separate implementations exist:
- `generateRandomBytes` in `add.go` (always base64)
- `generateValue` in `rotate.go` (supports randomBase64/randomHex/randomBytes)
- Inline generation in `update.go`

Consolidate into:

```go
func GenerateValue(gen *GeneratorConfig) ([]byte, error)
```

Supporting all three kinds.

### Step 8: Unify SealedSecret manifest building in `seal/`

Two divergent builders:
- `buildSealedSecretManifest` in `add.go` (uses `SealedSecret.ToYAML()`)
- `Engine.buildManifest` in `reseal/engine.go` (hand-rolled string builder)

**Bug:** These use inconsistent annotation formats:
- `add.go`: `sealedsecrets.bitnami.com/scope: namespace-wide`
- `engine.go`: `sealedsecrets.bitnami.com/namespace-wide: "true"`

Consolidate into `seal.SealedSecret.ToYAML()` as the single source of truth.
Verify which annotation format the controller expects before picking one.

### Step 9: Replace bubble sorts with `slices.Sort`

Two hand-rolled bubble sorts:
- `reminders.go` (sort expiring secrets by date)
- `reseal/engine.go` (`sortStrings` for deterministic key order)

Replace with `slices.SortFunc` / `slices.Sort`.

### Step 10: Fix `state/` to use `AtomicWriter`

Currently uses raw `os.WriteFile` — inconsistent with the rest of the codebase.
Switch to `files.AtomicWriter` for crash-safe state persistence.

---

## Phase 3 — CLI Simplification

### Step 11: Remove flags from `setup`

Delete from `setup.go`:
- `--project-id`
- `--controller-namespace`
- `--controller-name`
- `--skip-reminders`

Remove the `isNonInteractive` gating logic. `setup` is always interactive.
The wizard prompts cover everything these flags did.

### Step 12: Simplify `gcp bootstrap` to interactive

Remove all flags from `gcp_bootstrap.go`:
- `--project-id`, `--create-project`, `--billing-account-id`, `--folder-id`,
  `--organization-id`, `--github-repo`, `--default-branch-ref`, `--prefix`,
  `--service-account-id`

Convert to interactive wizard (like `setup`). Keep `--dry-run` (global) and
`--enable-reminders-api` as a prompt.

### Step 13: Refactor `setup` ↔ `gcp bootstrap` ↔ `discover` coupling

Replace the current approach of mutating package-level variables (`gcpProjectID`,
etc.) then calling `runGCPBootstrap`/`runDiscover`. Extract the core logic of
each into functions that accept parameters. Both standalone commands and `setup`
call those functions directly.

### Step 14: Merge `reencrypt` into `reseal`

Delete `reencrypt.go`. Enhance `reseal.go`:

- Add preamble: fetch cluster cert, compare fingerprint to repo cert
- If cert rotated: prompt user, write new cert, force `--all` reseal
- Add `--new-cert <path>` flag (from `reencrypt`)
- Add `--skip-cert-check` flag for offline/CI use
- Record state for all operations (current `reencrypt` skips state)
- Cert check only runs on `--all` invocations (skip for single-secret targeting)

**Decision:** Keep reading from GSM for cert rotation (matches existing behavior).
Update plan doc `50-reseal-and-rotate.md` to reflect this.

### Step 15: Split `validate` into `validate` + new `check`

**`validate`** (structural, CI-friendly):
- Config validity, metadata schema, manifest path existence, GSM version format
- Scope filters: `--cluster`, `--metadata`, `--gsm` (all run by default)
- Remove `--warn-days` (moves to `check`)

**`check`** (operational health, human-friendly):
- Cert validity and expiration
- Secret expiration / rotation due dates
- Default `--warn-days 30`
- Individual filters: `--cert`, `--expiry`

### Step 16: Add inline comments to `discover --non-interactive` stubs

In `generateMetadataStub` string builder in `discover.go`:

- Add `# See: https://github.com/shermanhuman/waxseal/docs/metadata-reference`
  link at the top
- Add comments explaining each field and valid values
- Include a commented-out computed key example at the bottom

---

## Phase 4 — Cleanup

### Step 17: Deduplicate remaining small items

- Merge duplicate `truncateString`/`truncate` functions (list.go, rotate.go)
- Move `parseIntList`/`formatDuration` to a shared location if needed elsewhere
- Unexport CLI-only functions that don't need to be visible

### Step 18: Update help text and docs

- Revise `Short`/`Long` descriptions on all modified Cobra commands
- Update `README.md` with simplified command surface
- Remove all references to deleted `reencrypt` command
- Update `AGENTS.md` to match new package structure

---

## DRY Violations Inventory (Pre-Refactor)

| # | Pattern | Count | Fixed In |
|---|---------|-------|----------|
| 1 | Config loading boilerplate | 10× | Step 6 |
| 2 | Metadata load-by-shortName | 7× | Step 5 |
| 3 | Metadata directory iteration | 7× | Step 5 |
| 4 | GSM store creation | 5× | Step 6 |
| 5 | Cert path + sealer creation | 4× | Step 6 |
| 6 | State recording pattern | 4× | Step 6 |
| 7 | Value generation | 3× | Step 7 |
| 8 | SealedSecret manifest builder | 2× | Step 8 |
| 9 | Bubble sort | 2× | Step 9 |
| 10 | `sanitizeGSMName` location | 5× | Step 2 |
| 11 | `FormatGSMResource` inline | 6× | Step 2 |
| 12 | String truncation duplicate | 2× | Step 17 |
| 13 | Template detection in wrong pkg | 2× | Step 3 |

---

## Commit Strategy

Each step should be a separate, reviewable commit. Run `go build ./...` and
`go test ./...` after every step. Phase 3 (CLI changes) should be a separate
PR or clearly labeled commits since they change user-facing behavior.
