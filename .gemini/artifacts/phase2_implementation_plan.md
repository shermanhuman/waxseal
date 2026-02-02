# WaxSeal Phase 2 Implementation Plan

This document tracks the remaining features from `.plan/` that are not yet implemented.

## Status Legend

- [ ] Not started
- [x] Complete

---

## Task 1: Retire Command

**Goal**: Allow operators to mark secrets as retired and optionally remove manifests.

**Plan Reference**: `10-cli.md` L111-113

### Implementation

- [ ] 1.1. Create `internal/cli/retire.go`
  - Mark metadata `status: retired`, set `retiredAt`, `retireReason`
  - Optionally delete manifest file with `--delete-manifest` flag
  - Optionally clear reminders with `--clear-reminders` flag
- [ ] 1.2. Add retirement validation to `validate` command
  - Warn if retired secret manifest still exists
- [ ] 1.3. Update README with `retire` command usage

### Tests

- [ ] **Unit test**: `retire` updates metadata correctly
- [ ] **Unit test**: `retire --delete-manifest` removes file
- [ ] **Integration test**: Retired secrets are skipped by `reseal --all`
- [ ] **Manual test**: Run `waxseal retire my-secret --dry-run`

### Verification Command

```bash
go test ./internal/cli/... -run TestRetire -v
```

---

## Task 2: Reencrypt Command

**Goal**: Refresh ciphertext using the cluster controller without accessing plaintext.

**Plan Reference**: `10-cli.md` L94-101, `50-reseal-and-rotate.md` L77-114

### Implementation

- [ ] 2.1. Create `internal/cli/reencrypt.go`
  - Requires kubeconfig access
  - Uses controller's re-encrypt endpoint (no plaintext needed)
  - Does NOT read from GSM
- [ ] 2.2. Create `internal/seal/reencrypt.go`
  - HTTP client to controller's re-encrypt API
  - OR use kubeseal library integration
- [ ] 2.3. Add `--kubeconfig` flag to root command
- [ ] 2.4. Update README with `reencrypt` command

### Tests

- [ ] **Unit test**: Mock controller response parsing
- [ ] **Integration test** (requires kind): Full reencrypt flow
- [ ] **Manual test**: `waxseal reencrypt my-secret --dry-run --kubeconfig ~/.kube/config`

### Verification Command

```bash
go test ./internal/seal/... -run TestReencrypt -v
```

---

## Task 3: Bootstrap Command

**Goal**: Push existing cluster secrets to GSM to establish GSM as source of truth.

**Plan Reference**: `10-cli.md` L114-117

### Implementation

- [ ] 3.1. Create `internal/cli/bootstrap.go`
  - Read Secret from cluster via kubeconfig
  - Write each key's value to GSM as version 1
  - Update metadata with GSM resource and version
- [ ] 3.2. Add secret reading capability to cluster client
- [ ] 3.3. Auto-sync reminders if enabled and keys have expiry

### Tests

- [ ] **Unit test**: GSM write mock verification
- [ ] **Integration test** (requires kind): Read real Secret, verify GSM writes
- [ ] **Manual test**: `waxseal bootstrap my-secret --dry-run`

### Verification Command

```bash
go test ./internal/cli/... -run TestBootstrap -v
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

## Task 5: Reminders Subcommands

**Goal**: Complete the reminders command tree.

**Plan Reference**: `10-cli.md` L141-148

### Implementation

- [ ] 5.1. Add `reminders list` - show upcoming expirations (default 90d)
- [ ] 5.2. Add `reminders clean` - remove calendar entries for retired secrets
- [ ] 5.3. Add `reminders setup` - interactive wizard (same as init)
- [ ] 5.4. Update README with all reminders subcommands

### Tests

- [ ] **Unit test**: `list` formatting with various expiry dates
- [ ] **Unit test**: `clean` identifies retired secrets
- [ ] **Manual test**: `waxseal reminders list`

### Verification Command

```bash
go test ./internal/cli/... -run TestRemindersList -v
```

---

## Task 6: Interactive Discover Prompts

**Goal**: Full interactive discover experience per plan.

**Plan Reference**: `10-cli.md` L40-76

### Implementation

- [ ] 6.1. Prompt for `shortName` confirmation
- [ ] 6.2. Prompt for scope if ambiguous
- [ ] 6.3. For each key, prompt:
  - Is this `computed` or `raw`?
  - If `raw`, choose rotation mode
  - Choose GSM linkage (link existing, create from cluster, create from input)
- [ ] 6.4. Add DATABASE_URL computed helper preset
- [ ] 6.5. Collect operator hints (rotation URLs, notes)
- [ ] 6.6. Collect expiration dates

### Tests

- [ ] **Unit test**: Prompt flow state machine
- [ ] **Manual test**: `waxseal discover` on test repo

### Verification Command

```bash
# Manual interactive test only
waxseal discover --repo testdata/infra-repo
```

---

## Task 7: Certificate Fingerprint Verification

**Goal**: Verify repo cert matches live controller cert.

**Plan Reference**: `40-kubernetes-integration.md` L19-31

### Implementation

- [ ] 7.1. Add `verifyAgainstCluster` config option (already exists, implement logic)
- [ ] 7.2. Fetch live cert from cluster controller
- [ ] 7.3. Compare fingerprints, error if mismatch
- [ ] 7.4. Add `--skip-cert-verify` flag for explicit override

### Tests

- [ ] **Unit test**: Fingerprint comparison logic
- [ ] **Integration test** (requires kind): Verify against real controller
- [ ] **Manual test**: `waxseal reseal --all` with mismatched cert

### Verification Command

```bash
go test ./internal/seal/... -run TestCertFingerprint -v
```

---

## Task 8: Golden Tests

**Goal**: Ensure stable YAML output format.

**Plan Reference**: `70-testing-and-ci.md` L29-32

### Implementation

- [ ] 8.1. Create `testdata/golden/` directory
- [ ] 8.2. Add golden test inputs (SealedSecret manifests)
- [ ] 8.3. Add expected outputs
- [ ] 8.4. Create `internal/reseal/golden_test.go`
  - Compare output against golden files
  - Stable key ordering
  - Deterministic formatting

### Tests

- [ ] **Unit test**: Golden comparisons pass
- [ ] **Update golden**: `go test ./... -update-golden` flag

### Verification Command

```bash
go test ./internal/reseal/... -run TestGolden -v
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

## Task 11: Auto-Bootstrap Offer

**Goal**: Offer to run discover if metadata is missing.

**Plan Reference**: `10-cli.md` L204-209

### Implementation

- [ ] 11.1. Check for `.waxseal/` at command start
- [ ] 11.2. If missing, print message and offer to run `discover`
- [ ] 11.3. Support `--yes` flag for non-interactive automation

### Tests

- [ ] **Unit test**: Detection logic
- [ ] **Manual test**: Run command in empty repo

### Verification Command

```bash
# Manual test in empty directory
waxseal list
# Should prompt to run discover
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
