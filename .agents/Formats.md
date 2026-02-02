---
description: Data format decisions for waxseal (YAML vs JSON)
---

# Formats (YAML vs JSON)

waxseal is opinionated about file/payload formats to keep usage obvious and behavior deterministic.

## Repo files

- Repo-local config is YAML: `.waxseal/config.yaml`
- Repo metadata is YAML: `.waxseal/metadata/*.yaml`

Rationale:

- YAML is the dominant human-authored config format in the Kubernetes/GitOps ecosystem.
- YAML supports comments (useful for operator-maintained repo config).
- YAML is less noisy than JSON for nested structures.

Constraints:

- Keep YAML simple: mappings, sequences, scalars.
- Avoid advanced YAML features (anchors/aliases/merge keys) in waxseal-authored output.
- Treat values that could be mis-typed (e.g., versions like `"1.0"`, Windows paths like `"c:"`, strings like `"yes"`) as strings and prefer quoting in examples.

Parsing requirements:

- Validate config/metadata against an explicit schema (Go structs) and fail closed on unknown fields.
- Never accept `latest` (or any GSM alias) in metadata; numeric GSM version pins only.

## GSM payloads

- Operator hints payloads are JSON.

## Reminders auth (v1)

- Reminder providers authenticate via Application Default Credentials (ADC).
- waxseal does not store Google Calendar credentials in Git or GSM.

Rationale:

- GSM payloads are machine-validated and treated as data blobs; JSON has a very clear, strict type system.
- JSON has broad schema tooling (JSON Schema) and canonicalization patterns.
- JSON avoids YAML-specific implicit typing surprises.

Note:

- YAML is a superset of JSON, but we still choose JSON for GSM payloads so the payload is unambiguous and easy to validate.
