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
 - “computed-external” is not a separate mode: computed keys may depend on external/manual inputs.

## Reencrypt (ciphertext refresh, cluster-driven)

Command: `waxseal reencrypt [--all | <shortName...>]`

Definition:

- Reencrypt updates ciphertext only, like reseal.
- Unlike reseal, it does not require plaintext (and does not read from GSM).
- This relies on the cluster/controller to perform re-encryption with the latest sealing key.

Use cases:

- Periodic refresh after controller key renewal.
- Reducing reliance on older sealing keys (still not a substitute for rotating underlying secret values).

User stories:

- As a GitOps operator, I want to refresh ciphertext across the repo after a controller key renewal so new commits are encrypted with the latest key, without changing secret values.
- As a team that keeps plaintext in GSM, I want a cluster-only path that never touches plaintext (and works even if GSM access is temporarily restricted).
- As a security-conscious maintainer, I want a safe “ciphertext refresh” tool that is explicitly not marketed as value-rotation.

Algorithm (per secret):

1. Resolve target manifest + expected namespace/name/scope from metadata.
  - If secret `status: retired`, refuse by default (require an explicit override).
2. Ensure we can reach the target cluster and Sealed Secrets controller (kubeconfig).
3. Re-encrypt the existing SealedSecret manifest without materializing plaintext.
  - This operates on the local manifest file; the SealedSecret does not need to already exist in the cluster.
  - Cluster access is still required because the controller performs the re-encryption with its private keys.
  - Implementation note (opinionated): use the upstream `kubeseal --re-encrypt` mechanism.
  - We should not depend on an arbitrary `kubeseal` on PATH; pin/bundle a known-good implementation.
4. Validate output is a `SealedSecret` (and name/namespace match expected).
5. Atomically replace the manifest on disk.

Idempotency:

- Running reencrypt repeatedly should be safe; ciphertext may change, but unsealed Secret must remain identical.
