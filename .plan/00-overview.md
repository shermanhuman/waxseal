# waxseal – Planning Overview (GSM-driven)

## System goal

Build a Go CLI that makes SealedSecrets GitOps-friendly while keeping plaintext out of Git.

Source of truth:

- All plaintext secret values live in Google Secret Manager (GSM) as secret *versions*.
- The Git repo stores:
  - `SealedSecret` manifests (ciphertext)
  - `.waxseal/metadata/*.yaml` mapping each SealedSecret key to a GSM secret+version (and computed keys).

Primary UX goals:

- `waxseal reseal --all` is a one-command, non-interactive ciphertext refresh.
  - It reads the exact GSM versions recorded in metadata and re-seals them with the current Sealed Secrets controller cert.
- `waxseal rotate` makes value rotation less painful.
  - It guides the operator, writes new GSM versions, then seals updated ciphertext to Git.

## Operational model

- `discover` is interactive adoption (read-only with respect to GSM):
  - registers existing SealedSecret manifests into `.waxseal/metadata/*.yaml`
  - fills “unknowns” by prompting and writing metadata only
  - does not write to GSM; importing plaintext into GSM is handled by `bootstrap`/`init`

- `reseal` is deterministic and non-interactive:
  - values come from GSM versions pinned in metadata
  - output changes only ciphertext (and never changes GSM)

- `rotate` changes values:
  - creates a new GSM version for one or more keys (generated or operator-provided)
  - updates metadata to point to the new version(s)
  - seals and commits the updated SealedSecret manifest(s)

- `retire` supports decommissioning:
  - mark metadata `status: retired`
  - optionally stage/validate removal of the SealedSecret manifest

## Hard requirements (for implementation)

- Never write plaintext to disk.
- Atomic writes for all manifest/metadata updates.
- Reseal must not accidentally change underlying values: metadata must pin numeric GSM versions.
- Prefer GSM best practices:
  - least-privilege IAM
  - ADC auth (Workload Identity / federation / `gcloud auth application-default login` locally)
  - pin secret versions (do not use aliases like `latest`)

Cloud setup (opinionated):

- Use a dedicated GCP project for waxseal secrets.
- Provision GCP resources via a script (no click-ops) so IAM and APIs are predictable.

## Metadata sensitivity

`.waxseal/metadata/*.yaml` is not plaintext secret material, but it can still be sensitive:

- it may reveal secret names, upstream vendors, internal hostnames, or usernames if you put them in URLs/templates/notes.

Design rule:

- Keep metadata minimally identifying by default.
- Do not store operator-authored hints (rotation URLs, notes, runbooks) directly in Git metadata by default.
  - Prefer storing them in GSM and referencing them by pinned version from metadata.
  - Treat computed `params` as potentially sensitive too (they often contain internal hostnames); prefer GSM-backed params for public repos.

Non-goal for v1:

- Encrypted-in-Git operator hints or encrypted metadata fields. Hints live in GSM; Git stays ciphertext-only + minimal metadata.

## Separation of concerns (plugin model)

waxseal is a CLI orchestrator with small, swappable backends.

- Secret Store plugin:
  - Responsible for storing plaintext secret values and non-secret-but-sensitive blobs (operator hints).
  - v1 store: Google Secret Manager (GSM).
  - Core waxseal code talks to an abstract interface (access pinned version, add version, optionally create secret).

- Reminder Provider plugin:
  - Responsible for creating/updating reminder entries.
  - v1 provider: Google Calendar.
  - v1 auth is ADC-only: reminder providers authenticate via Application Default Credentials.

Design intent:

- Adding a new store (e.g., AWS Secrets Manager, Vault) should not require changing reseal/rotate logic.
- Adding a new reminder provider should not require changing the secret-store implementation.
