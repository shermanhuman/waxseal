# Kubernetes Integration Plan

## Tooling notes

- waxseal should not depend on an arbitrary `kubeseal` found on PATH.
- v1 approach: integrate sealing/re-encryption logic as a library or bundle a pinned implementation.
- Local-dev escape hatch (optional): allow shelling out to a user-provided `kubeseal`, but only when explicitly enabled and with a clear warning.

## Controller discovery assumptions

Default installation conventions:

- Controller namespace: `kube-system`
- Service name: `sealed-secrets`
- Key secret label: `sealedsecrets.bitnami.com/sealed-secrets-key`

These must be configurable.

## Certificate handling

waxseal must support:

- Using a repo-pinned public cert (`keys/pub-cert.pem`).
- Optionally verifying that repo cert matches the live controller cert fingerprint.

Fingerprint policy:

- Default: verify fingerprint against live cluster before writing new SealedSecrets.
- If mismatch:
  - error by default (safe)
  - optional override flag to continue (explicitly dangerous)

## Plaintext source of truth

- GSM is the required plaintext source for `reseal` and for storing rotated values.
- Cluster plaintext reads are optional and only intended for adoption/bootstrapping ("take existing in-cluster Secret and populate GSM").

## RBAC

- Bootstrapping from cluster requires `get` access to `secrets` in target namespaces.
- Reseal/rotate do not require reading cluster secrets when GSM is configured.
- Validation/discovery does not require secrets access (unless fingerprint verification is enabled).

## Scope correctness

waxseal must preserve/compute the correct `kubeseal --scope` based on the SealedSecret scope configuration.
Incorrect scope is a common cause of “cannot decrypt sealed secret”.

## Controller naming pitfall (implementation note)

- The Sealed Secrets helm chart commonly installs the controller Service as `sealed-secrets`, while `kubeseal` defaults to `sealed-secrets-controller`.
- waxseal should not rely on `kubeseal` defaults; always pass controller name/namespace from config when talking to the cluster.
