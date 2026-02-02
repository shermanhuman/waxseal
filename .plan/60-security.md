# Security Plan (GSM-driven)

## Invariants

- Never write plaintext secret values to disk.
- Never log plaintext (including in debug logs, errors, stack traces).
- Keep plaintext in memory only as long as needed for sealing.

## Atomicity

- All writes are atomic:
  - SealedSecret manifests
  - `.waxseal/metadata/*.yaml`
- Validate before replace:
  - output is `kind: SealedSecret`
  - expected `metadata.name` and `metadata.namespace`

## GSM + IAM

- Authentication: Application Default Credentials.
- Authorization: least privilege.
  - `reseal`: only needs `AccessSecretVersion` for the pinned versions.
  - `rotate`: needs to add secret versions (and optionally create secrets during adoption).
- Version pinning is the default.
  - Reseal must read exactly the pinned version to guarantee “ciphertext only” changes.

Provisioning (opinionated):

- Avoid service account keys.
- Prefer Workload Identity Federation (e.g., GitHub OIDC) for CI and attached identities for workloads.
- Use dedicated service accounts per trust boundary (CI reseal/validate vs operator rotate/bootstrap).
- Prefer custom roles over basic roles.

## Calendar reminders (optional)

- Reminders use Google APIs via Application Default Credentials (ADC).
- waxseal must not write OAuth tokens/refresh tokens into the repo.
- Calendar entries must not include secret values; only identifiers like `shortName`, `keyName`, and expiration timestamps.

## Sealed Secrets correctness

- Scope must match existing scope (`strict`, `namespace-wide`, `cluster-wide`).
- Cert correctness:
  - default: verify repo cert fingerprint vs live controller cert
  - mismatch: fail closed unless explicitly overridden

## Logging/auditing

- Structured logs for non-sensitive events (`slog`).

Note: we rely on deterministic exit codes and stable logs for CI, not a separate structured output flag in v1.

## `.waxseal/metadata` encryption

Decision (v1): no.

- The metadata should not contain plaintext secret values.
- Encrypting everything adds friction (extra tooling, key distribution, CI complexity).

Rationale:

- Metadata must never contain plaintext secret values.
- Operator hints stay out of Git (stored in GSM and referenced by pinned version).
- If a repo might become public, avoid putting internal hostnames in metadata; use GSM-backed params (`computed.paramsRef`) instead.

Non-goal for v1:

- Encrypting metadata fields/files in Git. If we ever need this, it will be a separate design and key-management decision.

Constraint:

- `waxseal reseal --all` must remain non-interactive.
  - If encrypted metadata is used, decryption must be automated (available in CI via keys/identity).
