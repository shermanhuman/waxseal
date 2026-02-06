# Reseal and Rotate Algorithms

## Reseal (explicit)

Command: `waxseal reseal [--all | <shortName...>]`

Definition:

- Reseal updates ciphertext only. Underlying values remain unchanged.

Algorithm (per secret):

1. Resolve target manifest + expected namespace/name/scope from metadata.
  - If secret `status: retired`, refuse by default (require an explicit override).
2. Fetch plaintext inputs from GSM:
  - For each key where `keys[].source.kind: gsm`, read from `keys[].gsm.secretResource` at `keys[].gsm.version`.
  - GSM aliases (including `latest`) are not supported; versions are always pinned.
3. Compute computed keys:
  - For keys where `keys[].source.kind: computed`, recompute via `computed` using input values + params/paramsRef.
  - Fail on missing inputs or cycles.
4. Render a Kubernetes `Secret` object (in-memory) matching the expected keys and secret type.
5. Seal using `kubeseal --cert <repoCert> --scope <scope>`.
6. Validate output is a `SealedSecret` (and name/namespace match expected).
7. Atomically replace the manifest on disk.

Idempotency:

- Running reseal repeatedly should be safe. It will change ciphertext, but should not change structure/ordering.

## Rotate (values)

Command: `waxseal rotate [--all | <shortName...>]`

Definition:

- Rotate changes underlying values for keys marked `generated`.
- For `external/manual` keys, waxseal guides the operator.

Algorithm (per secret):

- Resolve all keys for the target secret into a single plaintext `Secret` payload, then seal once.

Per key resolution rules:

- Raw keys (`source.kind: gsm`):
  - If `rotation.mode: generated`:
    - Generate new value according to generator policy.
    - Add a new GSM secret version and update `keys[].gsm.version`.
  - If `rotation.mode: external|manual`:
    - Print operator hints (rotation URLs + notes) by reading `keys[].operatorHints` (GSM-backed) if configured.
    - Prompt operator:
      - Provide new value now (hidden input / stdin)
      - Reseal current value without change (reuses existing pinned GSM version)
      - Quit (safe exit)
    - If a new value is provided:
      - Add a new GSM secret version and update `keys[].gsm.version`.
  - If `rotation.mode: unknown`:
    - Refuse to rotate by default.
    - Suggested path: classify first (set `rotation.mode`) and connect to GSM.

- Computed keys (`source.kind: computed`):
  - Recompute after all raw inputs are resolved.
  - Fail fast on cycles or missing inputs.

Finalize:

1. Validate required keys are present and secret type matches expected.
2. Seal + validate + atomic write.
3. Atomically update metadata on disk (pinning new GSM versions) as part of the same operation.

Notes:

- We avoid a “skip” concept: the safe fallback is reseal-without-change.
- Rotate should never depend on reading plaintext from the cluster.
 - "computed-external" is not a separate mode: computed keys may depend on external/manual inputs.

## Cert Rotation (merged into `reseal`)

> **Decision (2026-02-06):** The former standalone `reencrypt` command is merged
> into `reseal`. The implementation reads from GSM (same path as normal reseal)
> rather than using `kubeseal --re-encrypt`. This keeps the architecture simpler
> and avoids a separate code path that would need its own testing.

When `reseal --all` is invoked, waxseal performs a cert-rotation check:

1. Fetch the cluster's current sealing certificate (via `kubeseal --fetch-cert`).
2. Compare the fingerprint to the repo certificate at `cert.repoCertPath`.
3. If fingerprints differ:
   - Prompt the user: "Cluster certificate has rotated. Update and reseal all?"
   - Write the new certificate to `cert.repoCertPath`.
   - Reseal all active secrets using the new certificate.
   - Record a cert-rotation event in state.
4. If fingerprints match: proceed with normal reseal.

Flags:

- `--new-cert <path>`: use a specific cert file instead of fetching from cluster.
- `--skip-cert-check`: bypass cluster cert comparison (for offline/CI use).

Cert check only runs on `--all` invocations (skip for single-secret targeting).

User stories:

- As a GitOps operator, I want `reseal --all` to automatically detect cert rotation
  so I don't need to remember a separate command.
- As a CI pipeline, I want `reseal --all --skip-cert-check` to re-seal without
  requiring cluster access.
