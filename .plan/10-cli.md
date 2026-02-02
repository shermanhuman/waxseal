# CLI Plan (Cobra)

## Command tree

- `waxseal init`
  - Happy-path onboarding command.
  - Orchestrates: `discover` → plan summary (no values) → confirmation → reminders setup (optional) → `bootstrap` → `reseal` → reminders sync.
  - Goal: one command to adopt an existing cluster/repo into the GSM-first, ciphertext-only Git model.

  Reminders setup (during `init`):

  - Ask: “Do you want expiration reminders?”
  - If yes, list available reminder plugins (v1: `google-calendar`) and prompt to select one.
  - Walk-through setup for the selected plugin and write the resulting config to `.waxseal/config.yaml`.
  - Auth is opinionated in v1: use Application Default Credentials (ADC).
    - waxseal does not ingest/store Google credentials in GSM.
    - `init` guides the operator through setting up ADC and verifies access.

  Google Calendar setup steps printed by `init` (v1):

  1) Enable the Calendar API in the selected Google Cloud project (one-time).
  2) Set up ADC on this machine:
     - Local dev: run `gcloud auth application-default login --scopes https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/calendar.events`
     - CI/automation: run waxseal with an attached service account identity (Workload Identity / federation / VM attached SA) that has the needed API access.
  3) Choose a calendar:
     - Default: `primary` (works for user-based ADC).
     - Recommended for teams: create a dedicated shared calendar and grant write access to the identity used by ADC, then set its `calendarId`.
  4) Verify access: waxseal performs a non-destructive Calendar API call (list calendars or create+delete a probe event) and fails closed with actionable error output.

  Note: GCP-side provisioning is not a script in v1. Use `waxseal gcp bootstrap` (or let `init` offer to run it) to keep setup deterministic and cross-platform.

- `waxseal discover`
  - Discover existing SealedSecret manifests in a repo and register them into `.waxseal/` metadata.
  - If `.waxseal/` does not exist, create it automatically.
  - Non-destructive (does not change manifests).
  - Interactive by default: prompts the operator to connect keys to GSM (recommended) and fill in intent gaps.
  - `--non-interactive` keeps the stub-only behavior (CI/automation): write metadata stubs with unknown rotation for raw keys and exit successfully.
  - Naming note: this is intentionally more explicit than `init`/`import`.

  Interactive prompts (initial scope):

  - For each discovered SealedSecret:
    - Confirm/choose `shortName` (default derived from `<namespace>/<name>`).
    - Confirm scope (`strict`/`namespace-wide`/`cluster-wide`) if not obvious.

  - For each key whose intent is unknown:
    - Choose whether the key is **computed** or a **raw value**:
      - `computed` (waxseal computes value from other keys; no GSM storage for the computed output)
      - `raw` (waxseal stores/reads the key value from GSM)

    - If `raw`, choose rotation intent (`rotation.mode`):
      - `generated` (waxseal generates value and stores it in GSM)
      - `external` (operator rotates in vendor; waxseal stores new value in GSM)
      - `manual` (operator-provided value; waxseal stores it in GSM)
      - `unknown` (defer)

    - Choose GSM linkage strategy (for `raw` keys):
      - Link to existing GSM secret + version
      - Create GSM secret + version by reading plaintext from cluster Secret (bootstrap)
      - Create GSM secret + version by prompting for plaintext (bootstrap)

  - Computed helper (optional but friendly):
    - Offer a built-in preset for common `DATABASE_URL` shapes (Postgres), then ask for:
      - host/port/db/sslmode constants
      - which keys provide `username` and `password`
    - Write a `computed` block into metadata.

  - Operator hints (recommended for `external`/`manual`):
    - Always store rotation URLs / runbook notes in GSM (not in Git).
    - During `discover`, collect rotation URLs and notes (optional) and record the intended hint secret ID in metadata.
    - Writing operator hints to GSM happens during `bootstrap`/`init`.

  - Expirations (optional, per key):
    - If the operator indicates a key has a real expiration, collect `expiresAt` (RFC3339) and record it in metadata.
    - Expiration metadata is always stored in Git (it is not secret), but reminders are only synced if configured.

- `waxseal list`
  - List registered secrets/keys and their rotation modes.
  - Default output includes an “expiry” column when present.

- `waxseal validate`
  - Validate repo + metadata consistency.
  - Intended for CI.
  - Expiration policy:
    - If a key is expired (`expiresAt` < now) and the secret is not retired: validation fails (exit code 2).
    - If a key expires soon (<= soon threshold; default 30d): validation warns.

- `waxseal reseal`
  - Explicit: produce new ciphertext under the current sealing cert/key.
  - Non-interactive by default.
  - Reads plaintext from GSM using the versions pinned in metadata.
  - Never changes underlying values and never mutates GSM.

- `waxseal reencrypt`
  - Explicit: re-encrypt existing SealedSecrets using the *latest controller sealing key* without requiring plaintext.
  - This is cluster-driven and requires Kubernetes API access (kubeconfig).
  - Does not read from or write to GSM.
  - Intended use: periodic refresh after controller key renewal.
  - Notes:
    - This is not a substitute for rotating real secret values.
    - This should be a separate command, not a mode of `reseal`.

- `waxseal rotate`
  - Rotate underlying secret values where possible, then seal.
  - By default, includes both generated + external/manual keys.
  - Writes new secret versions to GSM and updates metadata to pin those versions.
  - If the rotated key has `expiry.expiresAt`, prompt for the new expiration date/time (required).
  - If reminders are enabled, auto-sync reminders for the affected keys after a successful rotate.

- `waxseal retire`
  - Mark a secret as retired and (optionally) remove its SealedSecret manifest from the repo.
  - Intended workflow: mark retired first, then delete manifest once consumers are removed.

- `waxseal bootstrap`
  - Explicitly push plaintext from cluster into GSM to establish the GSM-as-source-of-truth model.
  - In practice, this is normally invoked via `waxseal init` (happy path).
  - If reminders are enabled, auto-sync reminders for any keys that have `expiry.expiresAt`.

- `waxseal gcp bootstrap`
  - Opinionated, deterministic provisioning for the GCP project that backs GSM.
  - Cross-platform (built into the Go binary); no standalone scripts.
  - Depends on `gcloud` being installed and already authenticated.
    - waxseal shells out to `gcloud` for project/IAM/API setup (avoid re-implementing billing/IAM edge cases).
    - If `gcloud` is missing or not authenticated, fail closed with actionable instructions.
  - Responsibilities (v1):
    - optionally create the project and link billing
    - enable required APIs (Secret Manager, IAM, STS, etc)
    - create service accounts for separate trust boundaries (CI vs operator)
    - create/update custom roles (least privilege)
    - bind IAM roles with IAM Conditions scoped by secret-name prefix
    - optionally configure Workload Identity Federation for GitHub Actions OIDC
  - Suggested flags (v1):
    - `--project-id` (required)
    - `--create-project` (optional)
    - `--billing-account-id`, `--folder-id` or `--org-id` (required if creating project)
    - `--github-repo <owner/repo>` + `--default-branch-ref refs/heads/main` (optional)
    - `--enable-reminders-api` (optional, enables Calendar API)
    - `--secrets-prefix waxseal-` (optional, default `waxseal-`)
    - `--dry-run` (optional)

- `waxseal reminders`
  - Surface and synchronize expiration reminders.
  - Subcommands:
    - `waxseal reminders list` (shows upcoming expirations; default window 90d)
    - `waxseal reminders sync` (create/update Google Calendar entries for all keys with `expiry.expiresAt`)
    - `waxseal reminders clean` (remove calendar entries for retired secrets or removed expirations)
    - `waxseal reminders setup` (interactive; same wizard as `init` without running discovery/bootstrap/reseal)

## Targeting rules

- Targets are primarily addressed by one or more `shortName` values.
- Common patterns:
  - `waxseal reseal --all`
  - `waxseal reseal breakdown-sites breakdown-admin`
  - `waxseal rotate --all`
  - `waxseal rotate breakdown-sites --key github_oauth_client_secret`

## Interactivity rules

- `reseal` should be non-interactive by default.
- `rotate`:
  - Generated keys are non-interactive.
  - External/manual keys require prompts to proceed.
  - No `--interactive` flag.

Reminders sync behavior (opinionated defaults):

- `waxseal reminders sync` is idempotent (safe to run repeatedly).
- When enabled in config, `rotate` and `bootstrap` run an implicit `reminders sync` for the touched keys as a final step.
- `init` runs `reminders sync` at the end (after `reseal`) and prints a short “upcoming expirations” summary.

## External/manual rotation prompts

For each key marked `external` or `manual`:

- Fetch and print operator hints (rotation URLs and notes) from `operatorHints` if present.
- Ask for one of:
  - Provide new value now (hidden input / stdin)
  - Reseal current value without change (reuses existing pinned GSM version)
  - Quit (safe exit)

Note: We intentionally avoid “skip” as a distinct concept. “Reseal current value without change” is the safe default fallback.

## Global flags (initial)

Design principle: keep flags minimal. Add knobs only when there is a concrete operator pain.

- `--repo <path>` (default `.`)
- `--config <path>` (default `.waxseal/config.yaml`)
- `--dry-run`
- `--yes` (only applies to runs that do not require external/manual prompts)

Determinism policy:

- GSM aliases (including `latest`) are not supported.
- Metadata must pin numeric GSM versions so `reseal` is deterministic and reviewable.

Discover-specific:

- `waxseal discover --non-interactive`
  - Never prompts.
  - Writes metadata stubs with `rotation.mode: unknown` for raw keys and no `computed` blocks.

Auto-bootstrap behavior:

- If a command that requires metadata is run and `.waxseal/` is missing, waxseal should:
  - Print a clear message that metadata is missing.
  - Offer to run `waxseal discover` automatically.
  - Support non-interactive automation via `--yes`.

Exit codes:

- `0`: success
- `2`: validation failed
- `>2`: runtime error
