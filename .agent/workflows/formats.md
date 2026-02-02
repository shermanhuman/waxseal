---
description: Data format decisions for waxseal (YAML vs JSON)
---

# Format Decisions

## Repo Files = YAML

- `.waxseal/config.yaml` - repo-local config
- `.waxseal/metadata/*.yaml` - per-secret metadata

**Why YAML:**

- Dominant in Kubernetes/GitOps ecosystem
- Supports comments
- Less noisy for nested structures

**Constraints:**

- Keep simple: mappings, sequences, scalars only
- Avoid anchors/aliases/merge keys in waxseal output
- Quote ambiguous values (`"1.0"`, `"yes"`, `"c:"`)

## GSM Payloads = JSON

- Operator hints stored in GSM use JSON format

**Why JSON:**

- Strict, unambiguous type system
- Broad schema tooling (JSON Schema)
- No YAML implicit typing surprises

## Parsing Rules

- Validate against explicit schema (Go structs)
- **Fail closed on unknown fields**
- Never accept `latest` or any GSM alias - numeric versions only

## Reminders Auth

- v1: Application Default Credentials (ADC) only
- No Google Calendar credentials stored in Git or GSM
