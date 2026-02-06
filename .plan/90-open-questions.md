# Open Questions

## Decisions (opinionated defaults)

- Module path: `github.com/shermanhuman/waxseal`.

- GSM versioning: always pin numeric versions in metadata.
	- GSM aliases (including `latest`) are not supported.
	- Rationale: waxseal must be deterministic; the same git commit should always seal the same plaintext inputs.

- Adoption/bootstrap commands:
	- Keep `discover` read-only (no writes to GSM).
	- Keep `bootstrap` write-capable (imports plaintext into GSM).
	- Provide one happy-path `setup` command that orchestrates: discover → plan summary (no values) → confirmation → bootstrap → reseal.

- Reseal modes:
	- Default `reseal` is GSM-driven (plaintext source-of-truth remains GSM).
	- Support controller-driven re-encryption now as a separate command: `waxseal reencrypt`.

- Sealing implementation:
	- Prefer integrating sealing logic as a library so waxseal is a single, cross-platform binary and we can pin a known-good implementation.
	- Avoid depending on an arbitrary `kubeseal` found on PATH.

- Secret types:
	- Accept any Kubernetes Secret `type`.
	- Provide first-class validation/rendering for the most common types (at least `Opaque`, `kubernetes.io/dockerconfigjson`, and `kubernetes.io/tls`).
	- For unknown types, treat `data`/`stringData` keys as opaque and only validate basic invariants.

- Computed values:
	- Prefer waxseal-side `computed` handling (deterministic, testable).
	- Use Sealed Secrets `spec.template` primarily for Secret metadata/type/immutable, not as the default computation engine.

- Non-secret config:
	- Do not introduce Google Parameter Manager in v1 (keep scope small).
	- If needed later, treat it as an optional integration; waxseal remains “secrets-first”.

- Operator hints:
	- Standardize on GSM-backed operator hints only (no encrypted-in-Git hints as a first-class feature).
	- Hint payload format: JSON with an explicit schema version.
	- Enforce GSM payload limit (64 KiB).

- Expirations and reminders:
	- Track expirations as non-secret per-key metadata (`keys[].expiry.expiresAt`).
	- Provide an optional reminders system with a pluggable provider.
	- v1 reminder provider: Google Calendar, creating/upserting Calendar *events* (not Google Tasks).
	- `setup` offers reminders setup, lists available providers, and guides credential setup.
	- Auth (v1): Application Default Credentials only.
		- Avoid service account keys where possible; prefer attached identity / federation / local user ADC.
		- No reminder credentials are stored in Git or GSM.

- Repo state:
	- Commit `.waxseal/state.yaml` only if it is strictly non-sensitive and helps determinism.
	- Put ephemeral caches in `.waxseal/cache/` and gitignore them.

## Remaining questions

None currently. If new requirements appear during implementation, capture them here and resolve them quickly.
