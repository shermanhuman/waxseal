# WaxSeal Phase 2 Implementation Plan

This document tracks the remaining features from `.plan/` that are not yet implemented.

## Status Legend

- [ ] Not started
- [x] Complete

---

## Task 1: Retire Command ✅

**Goal**: Allow operators to mark secrets as retired and optionally remove manifests.

**Plan Reference**: `10-cli.md` L111-113

### Implementation

- [x] 1.1. Create `internal/cli/retire.go`
  - Mark metadata `status: retired`, set `retiredAt`, `retireReason`
  - Optionally delete manifest file with `--delete-manifest` flag
  - Optionally clear reminders with `--clear-reminders` flag
- [x] 1.2. Add retirement validation to `validate` command
  - Warn if retired secret manifest still exists
- [ ] 1.3. Update README with `retire` command usage

### Tests

- [x] **Unit test**: `retire` updates metadata correctly
- [x] **Unit test**: `retire --delete-manifest` removes file
- [x] **Integration test**: Retired secrets are skipped by `reseal --all`
- [x] **Manual test**: Run `waxseal retire my-secret --dry-run`

### Verification Command

```bash
go test ./internal/cli/... -run TestRetire -v
```

---

## Task 2: Reencrypt Command ✅

**Goal**: Re-encrypt SealedSecrets when cluster certificate rotates.

**Plan Reference**: `10-cli.md` L94-101, `50-reseal-and-rotate.md` L77-114

### Implementation

- [x] 2.1. Create `internal/cli/reencrypt.go`
  - Compare current vs new certificate fingerprints
  - Fetch new cert from cluster via `kubeseal --fetch-cert`
  - Re-seal all active secrets with new certificate
  - Update repo certificate file
- [x] 2.2. Add `--new-cert` flag for offline cert provision
- [x] 2.3. Dry-run support for preview

### Tests

- [x] **Build test**: All packages compile
- [x] **Manual test**: `waxseal reencrypt --help`

### Verification Command

```bash
go build ./... && go test ./... -count=1
# All passed!
```

---

## Task 3: Bootstrap Command ✅

**Goal**: Push existing cluster secrets to GSM to establish GSM as source of truth.

**Plan Reference**: `10-cli.md` L114-117

### Implementation

- [x] 3.1. Create `internal/cli/bootstrap.go`
  - Read Secret from cluster via kubectl
  - Write each key's value to GSM via CreateSecretVersion
  - Update metadata with GSM resource and version
- [x] 3.2. Add CreateSecretVersion to store interface
- [x] 3.3. Add IsNotFound helper to core package

### Tests

- [x] **Build test**: All packages compile
- [x] **Unit test**: CreateSecretVersion in FakeStore
- [x] **Manual test**: `waxseal bootstrap --help`

### Verification Command

```bash
go build ./... && go test ./... -count=1
# All passed!
```

---

## Task 4: GCP Bootstrap Command

**Goal**: Deterministic GCP project provisioning for GSM.

**Plan Reference**: `10-cli.md` L119-139

### Implementation

- [ ] 4.1. Create `internal/cli/gcp_bootstrap.go`
  - Shell out to `gcloud` (required dependency)
  - Create project (optional), enable APIs, create SAs, bind IAM
- [ ] 4.2. Implement flags:
  - `--project-id` (required)
  - `--create-project`, `--billing-account-id`, `--folder-id`, `--org-id`
  - `--github-repo`, `--default-branch-ref`
  - `--enable-reminders-api`
  - `--secrets-prefix`
  - `--dry-run`
- [ ] 4.3. Check for `gcloud` on PATH, fail with instructions if missing
- [ ] 4.4. Update README with GCP setup section

### Tests

- [ ] **Unit test**: Command building with various flags
- [ ] **Manual test**: `waxseal gcp bootstrap --project-id=test --dry-run`

### Verification Command

```bash
go test ./internal/cli/... -run TestGCPBootstrap -v
```

---

## Task 5: Reminders Subcommands ✅

**Goal**: Complete the reminders command tree.

**Plan Reference**: `10-cli.md` L141-148

### Implementation

- [x] 5.1. Add `reminders list` - show upcoming expirations (default 90d)
- [x] 5.2. Add `reminders clean` - remove calendar entries for retired secrets
- [x] 5.3. Add `reminders setup` - interactive wizard (same as init)
- [ ] 5.4. Update README with all reminders subcommands

### Tests

- [x] **Unit test**: `list` formatting with various expiry dates
- [x] **Unit test**: `clean` identifies retired secrets
- [x] **Manual test**: `waxseal reminders list`

### Verification Command

```bash
go test ./internal/cli/... -run TestParse -v
go test ./internal/cli/... -run TestFormat -v
# All passed!
```

---

## Task 6: Interactive Discover Prompts ✅

**Goal**: Full interactive discover experience per plan.

**Plan Reference**: `10-cli.md` L40-76

### Implementation

- [x] 6.1. Enhanced discover with interactive wizard flow
- [x] 6.2. Prompt for GCP Project ID if not configured
- [x] 6.3. For each key, prompt for:
  - GSM resource (with auto-generated default)
  - Rotation mode (manual/generated/derived/static/unknown)
  - Expiry date (optional, YYYY-MM-DD format)
- [x] 6.4. Non-interactive mode for CI with `--non-interactive`
- [x] 6.5. Dry-run support shows generated metadata
- [x] 6.6. Clear next-steps guidance after completion

### Tests

- [x] **Build test**: All packages compile
- [x] **Manual test**: `waxseal discover --non-interactive --dry-run`

### Verification Command

````bash
go build ./... && go test ./... -count=1
# All passed!

---

## Task 7: Cert Expiry Verification ✅

**Goal**: Warn if sealing certificate is expiring or expired.

**Plan Reference**: `40-kubernetes-integration.md` L19-31

### Implementation

- [x] 7.1. Add certificate expiry methods to CertSealer
  - `GetCertNotAfter()`, `GetCertNotBefore()`
  - `IsExpired()`, `ExpiresWithinDays()`
  - `DaysUntilExpiry()`, `GetSubject()`, `GetIssuer()`
- [x] 7.2. Create `cert-check` command
  - Display certificate validity info
  - Warn if expiring within threshold (default: 30 days)
  - Exit with code 1 if expired, 2 if expiring (with --fail-on-warning)
- [x] 7.3. Add `--warn-days` and `--fail-on-warning` flags

### Tests

- [x] **Unit test**: Certificate expiry methods
- [x] **Unit test**: Expired certificate detection
- [x] **Unit test**: Expiring soon detection
- [x] **Manual test**: `waxseal cert-check --help`

### Verification Command

```bash
go test ./internal/seal/... -run TestCert -v
# All passed!
````

---

## Task 8: Golden Tests ✅

**Goal**: Ensure stable YAML output format.

**Plan Reference**: `70-testing-and-ci.md` L29-32

### Implementation

- [x] 8.1. Create `testdata/golden/` directory
- [x] 8.2. Add golden test inputs (SealedSecret manifests)
- [x] 8.3. Add expected outputs
- [x] 8.4. Create `internal/reseal/golden_test.go`
  - Compare output against golden files
  - Stable key ordering
  - Deterministic formatting

### Tests

- [x] **Golden test**: Opaque secret
- [x] **Golden test**: Docker registry secret with scope
- [x] **Golden test**: Computed keys
- [x] **Golden test**: Key ordering (alphabetical)
- [x] **Golden test**: Idempotency

### Verification Command

```bash
go test ./internal/reseal/... -run TestGolden -v
# All passed!
```

---

## Task 9: envtest Integration

**Goal**: In-process Kubernetes API server for testing.

**Plan Reference**: `70-testing-and-ci.md` L38-44

### Implementation

- [ ] 9.1. Add `sigs.k8s.io/controller-runtime/pkg/envtest` dependency
- [ ] 9.2. Create `tests/envtest/` directory
- [ ] 9.3. Test manifest discovery against real API types
- [ ] 9.4. Test schema correctness for rendered Secret objects
- [ ] 9.5. Test failure modes (missing keys, wrong namespaces)

### Tests

- [ ] **envtest test**: API type validation
- [ ] **envtest test**: Discovery targeting

### Verification Command

```bash
go test ./tests/envtest/... -v
```

---

## Task 10: kind E2E Tests

**Goal**: Full end-to-end validation with real Kubernetes.

**Plan Reference**: `70-testing-and-ci.md` L46-71

### Implementation

- [ ] 10.1. Create `tests/e2e/` directory
- [ ] 10.2. Create `tests/e2e/setup_test.go` - cluster lifecycle helpers
- [ ] 10.3. Install Sealed Secrets controller (pinned version)
- [ ] 10.4. Implement E2E scenarios:
  - [ ] 10.4.1. `reseal` produces valid SealedSecret
  - [ ] 10.4.2. Controller decrypts to expected Secret
  - [ ] 10.4.3. `reencrypt` refreshes ciphertext, Secret unchanged
- [ ] 10.5. Create `Makefile` targets:
  - `make e2e-setup` - create kind cluster
  - `make e2e-test` - run E2E suite
  - `make e2e-teardown` - delete cluster
- [ ] 10.6. Create GitHub Actions workflow for E2E (nightly)

### Tests

- [ ] **E2E test**: Full reseal flow
- [ ] **E2E test**: Full reencrypt flow
- [ ] **E2E test**: Rotate → reseal → decrypt

### Verification Command

```bash
make e2e-setup
make e2e-test
make e2e-teardown
```

---

## Task 11: Auto-Bootstrap Offer ✅

**Goal**: Offer to run discover if metadata is missing.

**Plan Reference**: `10-cli.md` L204-209

### Implementation

- [x] 11.1. Check for `.waxseal/` at command start
- [x] 11.2. If missing, print message and offer to run `discover`
- [x] 11.3. Support `--yes` flag for non-interactive automation

### Tests

- [x] **Unit test**: Detection logic (`requiresMetadata`)
- [x] **Unit test**: Missing config detection
- [x] **Unit test**: Missing metadata detection
- [x] **Unit test**: Existing metadata passes
- [x] **Manual test**: Run command in empty repo

### Verification Command

```bash
go test ./internal/cli/... -run TestRequires -v
go test ./internal/cli/... -run TestCheckMetadata -v
# All passed!
```

---

## Task 12: Operator Hints from GSM

**Goal**: Store rotation URLs and notes in GSM, not Git.

**Plan Reference**: `10-cli.md` L68-71, `00-overview.md` L66-73

### Implementation

- [ ] 12.1. Add `operatorHints` field to metadata schema
  - `gsm.secretResource` + `gsm.version` for hints blob
- [ ] 12.2. During `rotate`, fetch and display hints from GSM
- [ ] 12.3. During `discover`, collect hints and store in GSM
- [ ] 12.4. Hints are JSON blobs with `rotationUrl`, `notes` fields

### Tests

- [ ] **Unit test**: Hints parsing and display
- [ ] **Integration test**: Fetch hints during rotate

### Verification Command

```bash
go test ./internal/cli/... -run TestOperatorHints -v
```

---

## Task 13: Update README

**Goal**: Document all new commands and features.

### Implementation

- [ ] 13.1. Add `retire` command section
- [ ] 13.2. Add `reencrypt` command section
- [ ] 13.3. Add `bootstrap` command section
- [ ] 13.4. Add `gcp bootstrap` command section
- [ ] 13.5. Add complete `reminders` subcommands
- [ ] 13.6. Add E2E testing section
- [ ] 13.7. Add GCP project setup guide

### Verification

- [ ] **Manual review**: README is accurate and complete

---

## Task 14: Update AGENTS.md

**Goal**: Document new packages and testing patterns.

### Implementation

- [ ] 14.1. Add new packages to structure
- [ ] 14.2. Document envtest patterns
- [ ] 14.3. Document E2E test patterns
- [ ] 14.4. Add golden test instructions

### Verification

- [ ] **Manual review**: AGENTS.md is accurate

---

## Implementation Order (Recommended)

| Priority | Task                          | Reason                            |
| -------- | ----------------------------- | --------------------------------- |
| 1        | Task 1: Retire                | Simple, enables secret lifecycle  |
| 2        | Task 5: Reminders subcommands | Completes existing feature        |
| 3        | Task 8: Golden tests          | Quick win, improves test coverage |
| 4        | Task 11: Auto-bootstrap       | UX improvement                    |
| 5        | Task 3: Bootstrap             | Enables adoption workflow         |
| 6        | Task 2: Reencrypt             | Requires cluster access           |
| 7        | Task 7: Cert verification     | Security feature                  |
| 8        | Task 6: Interactive discover  | Complex, many prompts             |
| 9        | Task 12: Operator hints       | Enhancement                       |
| 10       | Task 4: GCP bootstrap         | Nice-to-have                      |
| 11       | Task 9: envtest               | Test infrastructure               |
| 12       | Task 10: kind E2E             | Test infrastructure               |
| 13       | Task 13-14: README/AGENTS     | Documentation                     |

---

## Quick Start

To begin implementation:

```bash
# Run existing tests first
go test ./... -count=1

# Start with Task 1 (Retire)
# Then run specific tests after each implementation
```
