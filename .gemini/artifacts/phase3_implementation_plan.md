# Phase 3: Secret Management Commands

## Overview

This phase adds commands for the complete secret lifecycle:

- **add**: Create new secrets from scratch
- **update**: Modify secret values
- **show**: View secret metadata
- **reminders integration**: Add calendar setup to setup wizard

## Task Order Rationale

1. **show** first - read-only, builds familiarity with metadata handling
2. **add (non-interactive)** - core creation logic, easier to test
3. **add (interactive)** - builds on non-interactive with huh prompts
4. **update** - depends on having secrets to update
5. **reminders in setup** - enhancement to existing workflow

---

## Task 1: Implement `show` Command

**Purpose**: Display secret metadata, keys, rotation config, and GSM references without exposing values.

**Implementation**:

- Read metadata file for given shortName
- Format and display: status, namespace, keys, rotation modes, expiry dates
- Support `--json` and `--yaml` output formats
- Exit code 1 if secret not found

**Essential behaviors**:

- [ ] Loads metadata correctly
- [ ] Displays all key names
- [ ] Shows rotation mode per key
- [ ] Shows expiry dates if set
- [ ] Handles retired secrets differently (warn or skip)
- [ ] Returns error for non-existent secrets

---

## Task 2: Tests for `show` Command

**Unit tests** (`internal/cli/show_test.go`):

- `TestShowCommand_Success` - valid secret, all fields displayed
- `TestShowCommand_NotFound` - returns appropriate error
- `TestShowCommand_RetiredSecret` - shows retired status
- `TestShowCommand_JSONOutput` - valid JSON structure
- `TestShowCommand_YAMLOutput` - valid YAML structure

**E2E tests** (`tests/e2e/show_test.go`):

- `TestE2E_Show_DisplaysMetadata` - end-to-end with real metadata file
- `TestE2E_Show_HandlesMultipleKeys` - secret with 3+ keys displays all
- `TestE2E_Show_ErrorsOnMissing` - exit code 1 for missing secret

---

## Task 3: Implement `add` Command (Non-Interactive)

**Purpose**: Create a new secret with metadata, GSM entries, and SealedSecret manifest via flags.

**CLI signature**:

```bash
waxseal add <shortName> \
  --namespace=<ns> \
  --key=<keyName> \          # repeatable
  --gsm-prefix=<prefix> \    # or auto-generate from project/shortName
  --rotation-mode=manual \
  --manifest-path=<path> \
  --scope=strict|namespace-wide|cluster-wide \
  --dry-run
```

**Implementation flow**:

1. Validate inputs (namespace required, at least one key)
2. Generate GSM resource paths from prefix + keyName
3. For each key: prompt for value OR generate random (--generate-random)
4. Push values to GSM, get version numbers
5. Create metadata file
6. Create SealedSecret manifest (using cert to seal)
7. Output success summary

**Essential behaviors**:

- [ ] Creates metadata file with correct structure
- [ ] Creates GSM secrets with correct resource paths
- [ ] Creates SealedSecret manifest at specified path
- [ ] Dry run shows what would happen without creating anything
- [ ] Validates namespace is provided
- [ ] Validates at least one key is specified
- [ ] Handles GSM permission errors gracefully

---

## Task 4: Tests for `add` (Non-Interactive)

**Unit tests** (`internal/cli/add_test.go`):

- `TestAddCommand_ValidatesNamespace` - errors if namespace missing
- `TestAddCommand_ValidatesKeys` - errors if no keys specified
- `TestAddCommand_GeneratesGSMPaths` - correct path construction
- `TestAddCommand_DryRunCreatesNothing` - no files/GSM changes
- `TestAddCommand_MetadataStructure` - output matches schema

**Integration tests** (`tests/integration/add_test.go`):

- `TestAdd_CreatesMetadataFile` - file exists with correct content
- `TestAdd_CreatesManifestFile` - SealedSecret at correct path
- `TestAdd_GSMInteraction` - mock GSM receives correct calls

**E2E tests** (`tests/e2e/add_test.go`):

- `TestE2E_Add_CreatesCompleteSecret` - full flow with real cert
- `TestE2E_Add_DryRun` - no side effects
- `TestE2E_Add_MultipleKeys` - 3 keys all created correctly
- `TestE2E_Add_AlreadyExists` - errors if shortName exists

---

## Task 5: Implement `add` Command (Interactive)

**Purpose**: Wizard-style secret creation using huh prompts.

**Interactive flow**:

1. Prompt: Short name (if not provided as arg)
2. Prompt: Namespace
3. Prompt: Secret type (Opaque, TLS, etc.)
4. Prompt: Manifest output path (suggest default)
5. Loop: Add keys
   - Key name
   - Value source: enter now / generate random / skip (enter later)
   - Rotation mode
   - Expiry (optional)
6. Confirm and create

**Essential behaviors**:

- [ ] All prompts use huh for arrow-key navigation
- [ ] Can add multiple keys in one session
- [ ] Validates inputs inline (empty key names rejected)
- [ ] Shows summary before creating
- [ ] Falls back to non-interactive if stdin is not TTY
- [ ] `--non-interactive` flag forces flag-based mode

---

## Task 6: Tests for `add` (Interactive)

**Unit tests** (extend `internal/cli/add_test.go`):

- `TestAddCommand_NonInteractiveFlag` - uses flags not prompts
- `TestAddCommand_DetectsTTY` - falls back when no TTY

**E2E tests** (extend `tests/e2e/add_test.go`):

- `TestE2E_Add_NonInteractiveMode` - `--non-interactive` works

Note: Interactive huh prompts are difficult to test automatically. Manual testing required for wizard flow. Document test plan in comments.

---

## Task 7: Implement `update` Command

**Purpose**: Update a secret key's value in GSM and reseal the SealedSecret.

**CLI signature**:

```bash
# Interactive (prompts for value)
waxseal update <shortName> <keyName>

# From stdin
echo "new-value" | waxseal update <shortName> <keyName> --stdin

# Generate random
waxseal update <shortName> <keyName> --generate-random --length=32
```

**Implementation flow**:

1. Load metadata for shortName
2. Find keyName in metadata
3. Get new value (prompt / stdin / generate)
4. Push new version to GSM
5. Update metadata with new version number
6. Reseal the SealedSecret
7. Output success

**Essential behaviors**:

- [ ] Bumps GSM version correctly
- [ ] Updates metadata version reference
- [ ] Reseals SealedSecret with new value
- [ ] Errors if shortName not found
- [ ] Errors if keyName not in secret
- [ ] Secure input (no echo for password prompts)
- [ ] `--stdin` reads one line from stdin

---

## Task 8: Tests for `update` Command

**Unit tests** (`internal/cli/update_test.go`):

- `TestUpdateCommand_SecretNotFound` - appropriate error
- `TestUpdateCommand_KeyNotFound` - key doesn't exist in secret
- `TestUpdateCommand_StdinMode` - reads from stdin correctly
- `TestUpdateCommand_GenerateRandom` - produces correct length

**Integration tests** (`tests/integration/update_test.go`):

- `TestUpdate_BumpsGSMVersion` - mock verifies new version created
- `TestUpdate_UpdatesMetadata` - version in file changes
- `TestUpdate_TriggersReseal` - SealedSecret modified

**E2E tests** (`tests/e2e/update_test.go`):

- `TestE2E_Update_FullFlow` - GSM updated, metadata updated, manifest updated
- `TestE2E_Update_GenerateRandom` - random value works
- `TestE2E_Update_DryRun` - shows what would happen
- `TestE2E_Update_RetiredSecret` - errors for retired secrets

---

## Task 9: Integrate Reminders Setup into Setup

**Purpose**: Offer calendar reminder setup as optional step in setup wizard.

**Changes to setup**:

1. After bootstrap step, add prompt:
   ```
   ? Set up expiration reminders (Google Calendar)?
     ▸ Yes (requires Calendar API enabled)
       No, skip for now
   ```
2. If yes, show requirements and run reminders setup inline
3. Update config with reminders section

**Essential behaviors**:

- [ ] Only shown in interactive mode
- [ ] Skippable without breaking setup
- [ ] Config updated atomically
- [ ] Prerequisites displayed clearly
- [ ] Works with existing reminders setup wizard logic

---

## Task 10: Tests for Reminders in Setup

**Unit tests** (extend `internal/cli/setup_test.go`):

- `TestSetup_SkipsRemindersNonInteractive` - no prompts in CI mode

**E2E tests** (extend `tests/e2e/setup_test.go`):

- `TestE2E_Setup_NonInteractive_NoReminders` - config doesn't have reminders section

---

## Verification Checklist

After all tasks complete:

- [ ] `waxseal add my-secret --namespace=default --key=api_key --non-interactive` works
- [ ] `waxseal add my-secret` runs interactive wizard
- [ ] `waxseal update my-secret api_key --generate-random` updates value
- [ ] `waxseal show my-secret` displays metadata
- [ ] `waxseal show my-secret --json` outputs valid JSON
- [ ] `waxseal setup` offers reminders setup
- [ ] All unit tests pass: `go test ./...`
- [ ] All E2E tests pass: `docker compose -f docker-compose.e2e.yaml up --build`
- [ ] README updated with new commands

---

## Estimated Effort

| Task                          | Effort        |
| ----------------------------- | ------------- |
| Task 1: show command          | 1 hour        |
| Task 2: show tests            | 30 min        |
| Task 3: add (non-interactive) | 2 hours       |
| Task 4: add tests             | 1 hour        |
| Task 5: add (interactive)     | 1.5 hours     |
| Task 6: add interactive tests | 30 min        |
| Task 7: update command        | 1.5 hours     |
| Task 8: update tests          | 1 hour        |
| Task 9: reminders in setup    | 1 hour        |
| Task 10: reminders tests      | 30 min        |
| **Total**                     | **~10 hours** |
