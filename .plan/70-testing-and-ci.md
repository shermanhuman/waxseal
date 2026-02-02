# Testing and CI Plan

This is a CLI that touches two hard dependencies (Kubernetes + GSM). The plan below is intentionally opinionated: fast tests always, realistic tests on a schedule, and no “mystery” emulators.

## Unit tests

- Config parsing and schema validation.
- Metadata resolution and targeting.
- YAML parsing and rendering.
- Scope selection (`strict` vs `namespace-wide` vs `cluster-wide`).
- Atomic writer behavior (never writes empty/partial output).
- GSM client wrapper behavior:
	- access pinned version
	- add new version
	- never read `latest` (aliases are not supported)
- Reminder scheduler behavior:
	- computes reminder times from `expiresAt` + `leadTimeDays`
	- idempotent upsert behavior (same inputs => same calendar update intent)
- Combined transaction behavior:
	- rotate updates GSM version pin + manifest atomically

Recommendation:

- Treat GSM as an interface at the waxseal boundary and test most behavior with an in-memory fake (map of `secretResource+version -> bytes`).
- Keep Google client library usage in a thin adapter so tests don’t need credentials or network.

Same rule for Calendar: keep it behind an interface and test with a fake.

## Golden tests

- Input SealedSecret manifests → expected output shape.
- Ensure stable key ordering in YAML output (as much as practical).

## Integration tests

We use two tiers, with clear defaults:

1) `envtest` integration (default for PR CI)

- Use controller-runtime `envtest` when we need a Kubernetes API server in-process.
- Use it to validate:
	- manifest discovery + targeting against real API types
	- schema/field correctness for rendered `Secret` objects (before sealing)
	- failure modes (missing keys, wrong namespaces, etc.)

2) `kind` E2E (default for nightly / release CI)

- Use `kind` as the single supported E2E cluster runner.
	- Rationale: closest to “real Kubernetes” behavior; widely used in CI.
- E2E validates the full promise:
	- waxseal produces a SealedSecret from GSM inputs
	- apply it to the cluster
	- Sealed Secrets controller decrypts it into the expected `Secret`
	- waxseal `reencrypt` refreshes ciphertext and the unsealed `Secret` remains identical

Note: `k3d` is a valid local-dev alternative, but we should not support multiple cluster runners in CI initially.

Version pinning (required for CI determinism):

- `envtest`: pin the Kubernetes asset version (api-server/etcd) instead of “latest”, and cache the downloaded assets in CI.
- `kind`: pin the node image tag (`kindest/node:vX.Y.Z`) and keep it aligned with the production cluster minor version.
- Sealed Secrets controller: install a pinned controller version (pinned Helm chart or pinned manifest URL) and assert the controller image tag is pinned.
- `kubeseal`/sealing implementation: pin the sealing implementation used by waxseal (don’t depend on an unpinned binary on PATH).

Test fixtures:

- Keep a tiny “fixture GitOps repo” under `testdata/infra-repo/` (or similar):
	- a couple of representative SealedSecret manifests (Opaque + dockerconfigjson)
	- corresponding `.waxseal/metadata/` samples
	- a minimal `.waxseal/config.yaml`
- E2E tests run waxseal against this fixture repo and assert the outputs + cluster behavior.

GSM in tests:

- Secret Manager does not have a commonly-used local emulator.
- Recommendation (default): narrow interface + in-memory implementation.
  - This keeps tests fast, deterministic, and hermetic.
- Later (only if we need it): fake gRPC server + endpoint override to validate request/response wiring.

## CI checks

On PRs (required):

- `go test ./...` (unit + golden + envtest)
- `go vet ./...`

Nightly (recommended):

- `kind` E2E suite (slower, but catches integration drift)

On release tags:

- Build matrix artifacts + checksums + SBOM (see release plan).
- Run `kind` E2E suite as a release gate.
