---
name: waxseal
description: Generator kinds, computed keys, template payloads, and Garage S3 credential patterns. Use when working on key creation, rotation, or template features.
---

# WaxSeal Computed Keys & Generators

## Generator Kinds

WaxSeal supports two generator kinds for producing secret material:

| Kind           | Output                    | Use case                              |
| -------------- | ------------------------- | ------------------------------------- |
| `randomBase64` | URL-safe base64 string    | Tokens, passwords, encryption keys    |
| `randomHex`    | Hex-encoded string        | Garage S3 keys, hex-format secrets    |

Generator kind is stored in metadata at `rotation.generator.kind` and used by `rotate` to produce matching replacements.

## Computed Keys (Two Types)

### 1. Derived (Cross-Reference)

Computed from other keys via `inputs[]` references. No GSM payload — value is calculated at reseal time.

```yaml
source:
  kind: computed
computed:
  kind: template
  template: "postgresql://{{username}}:{{secret}}@{{host}}:{{port}}/{{database}}"
  inputs:
    - var: username
      ref: { keyName: username }
    - var: host
      ref: { shortName: shared-postgres, keyName: host }
```

### 2. GSM-Backed Templated

Self-contained JSON payload in GSM. The `{{secret}}` portion is rotatable independently.

```yaml
source:
  kind: computed
computed:
  kind: template
  template: "GK{{secret}}"
  gsm:
    secretResource: projects/p/secrets/s
    version: "3"
rotation:
  mode: generated
  generator:
    kind: randomHex
    bytes: 12
```

GSM stores a JSON payload:

```json
{
  "schemaVersion": 1,
  "type": "templated",
  "template": "GK{{secret}}",
  "values": {},
  "secret": "a1b2c3d4e5f6a1b2c3d4e5f6",
  "generator": { "kind": "randomHex", "bytes": 12 },
  "computed": "GKa1b2c3d4e5f6a1b2c3d4e5f6"
}
```

The SealedSecret gets the `computed` value. `rotate` regenerates `secret`, recomputes, and stores a new GSM version.

## Prefixed Key Auto-Detection

`template/detect.go` has `wellKnownPrefixes` for auto-detecting templated patterns:

| Prefix | Project | Format                        | Generator    |
| ------ | ------- | ----------------------------- | ------------ |
| `GK`   | Garage  | `GK` + 24 hex chars (12 bytes) | `randomHex`  |

`DetectPrefixedKey()` matches by prefix + key name hints + format validation.
`WellKnownPrefixes()` exposes the list for CLI auto-selection.

When `addkey` sees a template matching a known prefix, it auto-selects the correct generator kind and byte count.

## CLI Flags

### `--generator` (addkey, updatekey)

Selects generator kind. Default: `randomBase64`.

```bash
waxseal addkey garage-creds --generator=randomHex --random-length=12
```

### `--key=name:template=...` (addkey)

Creates a templated key with prefix:

```bash
--key=access-key:template=GK{{secret}}   # Templated with GK prefix
--key=password:random                     # Plain generated
--key=username                            # Static (prompts for value)
```

## Shared Helpers (`cli/keys.go`)

| Function                | Purpose                                           |
| ----------------------- | ------------------------------------------------- |
| `ParseKeySpec(spec)`    | Parses `name`, `name:random`, `name:template=...` |
| `PromptGeneratorKind()` | TUI prompt for randomBase64/randomHex              |
| `PromptRotationMode()`  | TUI prompt for static/generated/external           |
| `PromptSecretValue()`   | Secure password-style input                        |
| `ValidateGeneratorKind()` | Validates kind string                            |
| `BuildGeneratorConfig()` | Creates `GeneratorConfig` with validation         |

All key management commands (`addkey`, `updatekey`, `edit` wizard) use these shared helpers.

## Garage S3 Credentials

Garage access keys use `GK` prefix + 24 hex chars. Secret keys use 64 hex chars.

Correct invocation:

```bash
waxseal addkey garage-creds \
  --namespace=default \
  --key=access-key:template=GK{{secret}} \
  --key=secret-key:random \
  --generator=randomHex \
  --random-length=12 \
  --manifest-path=apps/infrastructure/garage/creds-sealed.yaml
```

The `access-key` template auto-detects `randomHex` + 12 bytes from the `GK` prefix even if `--generator` is not specified.

## Common Mistakes

- Using `randomBase64` with `GK{{secret}}` — produces invalid Garage keys with `+`, `/`, `=` chars
- Forgetting `--random-length=12` for Garage access keys (default 32 bytes = 64 hex chars, too long)
- Running `waxseal rotate` on keys with wrong generator config — check metadata first with `waxseal meta showkey`
