# Task: WaxSeal CLI Refactoring — Command Hierarchy & `edit` Wizard

## Terminology Standard (aligned with K8s/SealedSecrets)

| Concept               | WaxSeal Term | K8s Term                  | Example                                    |
| :-------------------- | :----------- | :------------------------ | :----------------------------------------- |
| SealedSecret resource | **secret**   | SealedSecret / Secret     | `default-breakdown-sites-secrets`          |
| Individual data entry | **key**      | data key (key-value pair) | `breakdown_sites_postmark_api_key`         |
| YAML file on disk     | **manifest** | manifest                  | `apps/breakdown-sites/sealed-secrets.yaml` |

---

## Complete Command Audit

### Every current command → new home

| #   | Old Command                             | New Command                       | Help Tier | User Story                                                                                      | Duplication Notes                                                                                                     |
| :-- | :-------------------------------------- | :-------------------------------- | :-------- | :---------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
| 1   | `add <shortName> --key <k>`             | `addkey <shortName> --key <k>`    | Advanced  | "I need to add a Postmark API key to my existing secrets manifest via script/CI"                | **Primary path now** — adding to existing. Creating a new manifest is secondary                                       |
| 2   | `update <shortName> <keyName>`          | `updatekey <shortName> <keyName>` | Advanced  | "I need to rotate the webhook secret value and reseal the manifest"                             | Remove `--create` flag (that was duplication with `add`)                                                              |
| 3   | `update <shortName> <keyName> --create` | _(removed)_                       | —         | —                                                                                               | **DUPLICATE of `add`** — delete this flag entirely                                                                    |
| 4   | `retire <shortName>`                    | `retirekey <shortName>`           | Advanced  | "I'm decommissioning an old secret and need to mark it retired"                                 | No change to behavior                                                                                                 |
| 5   | `show <shortName>`                      | `meta showkey <shortName>`        | Primary   | "I need to see the metadata, keys, rotation modes, and GSM refs for a secret"                   |                                                                                                                       |
| 6   | `list`                                  | `meta list secrets`               | Primary   | "What secrets are registered and what's their status?"                                          |                                                                                                                       |
| 7   | _(new)_                                 | `meta list keys <shortName>`      | Primary   | "What keys are in this secret and what are their rotation modes?"                               | Currently done via `show` — **`show` is overloaded**. `list keys` gives a table, `showkey` gives full detail          |
| 8   | `rotate <shortName> [keyName]`          | `rotate <shortName> [keyName]`    | Primary   | "A key is due for rotation — auto-generate or prompt me for the new value"                      |                                                                                                                       |
| 9   | `reseal [shortName\|--all]`             | `reseal [shortName\|--all]`       | Primary   | "Certificate was rotated, I need to re-encrypt all manifests"                                   |                                                                                                                       |
| 10  | `check`                                 | `check`                           | Primary   | "Run all health checks before I push this commit"                                               | **Absorbs `cert-check` + `validate`** — runs all by default                                                           |
| 11  | `check --cert`                          | `check cert`                      | Advanced  | "I only care about certificate expiry right now"                                                |                                                                                                                       |
| 12  | `check --expiry`                        | `check expiry`                    | Advanced  | "Are any keys approaching their expiration dates?"                                              |                                                                                                                       |
| 13  | `cert-check`                            | _(removed)_                       | —         | —                                                                                               | **DUPLICATE of `check --cert`** — `check.go` already has `--cert` flag that does the same thing as `cert-check`       |
| 14  | `validate`                              | `check metadata`                  | Advanced  | "Validate schema integrity: config valid, manifests exist, versions numeric, no hostname leaks" | **Partially duplicates `check`** — structural validation vs operational health. Now unified under `check`             |
| 15  | `validate --cluster`                    | `check cluster`                   | Advanced  | "Do my metadata keys match what's actually in the Kubernetes cluster?"                          | Requires `kubectl`                                                                                                    |
| 16  | `validate --gsm`                        | `check gsm`                       | Advanced  | "Do the GSM secrets referenced in metadata actually exist?"                                     | Requires GSM auth                                                                                                     |
| 17  | `discover`                              | `discover`                        | Advanced  | "I have existing SealedSecret manifests in Git — scan and register them"                        |                                                                                                                       |
| 18  | `bootstrap [shortName]`                 | `gsm bootstrap [shortName]`       | Advanced  | "Push secret values from cluster into GSM to establish source of truth"                         |                                                                                                                       |
| 19  | `gcp bootstrap`                         | _(merged into `setup`)_           | —         | "Set up GCP project, enable APIs, create service account"                                       | **setup already calls `executeGCPBootstrap`** — keep `gcp bootstrap` as advanced alias if standalone use still needed |
| 20  | `setup`                                 | `setup`                           | Primary   | "First time using WaxSeal — walk me through everything"                                         |                                                                                                                       |
| 21  | `reminders sync`                        | `reminders sync`                  | Advanced  | "Push expiry dates to Google Calendar/Tasks"                                                    |                                                                                                                       |
| 22  | `reminders list`                        | `reminders list`                  | Advanced  | "What secrets are expiring in the next 90 days?"                                                |                                                                                                                       |
| 23  | `reminders clear <shortName>`           | `reminders clear <shortName>`     | Advanced  | "Remove calendar events for a retired secret"                                                   |                                                                                                                       |
| 24  | `reminders setup`                       | `reminders setup`                 | Advanced  | "Configure Google Calendar/Tasks reminder integration"                                          |                                                                                                                       |
| 25  | `completion`                            | `completion` _(hidden)_           | Hidden    | "Generate shell autocompletion scripts"                                                         | Cobra built-in — useful but shouldn't clutter help                                                                    |
| 26  | _(new)_                                 | `edit`                            | Primary   | "I need to manage keys interactively — walk me through it"                                      | Orchestrates `addkey`/`updatekey`/`retirekey` via TUI                                                                 |
| 27  | _(new)_                                 | `edit addkey`                     | Primary   | "Jump straight into the interactive add-key wizard"                                             |                                                                                                                       |
| 28  | _(new)_                                 | `edit updatekey`                  | Primary   | "Jump straight into the interactive update-key wizard"                                          |                                                                                                                       |
| 29  | _(new)_                                 | `edit retirekey`                  | Primary   | "Jump straight into the interactive retire-key wizard"                                          |                                                                                                                       |
| 30  | _(new)_                                 | `help advanced`                   | Primary   | "Show me the power-user / CI / troubleshooting commands"                                        |                                                                                                                       |

### Identified Duplications

| Duplication                         | Resolution                                                                                                                           |
| :---------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| `cert-check` ≡ `check --cert`       | Delete `cert-check`. Promote to `check cert` subcommand                                                                              |
| `update --create` ≡ `add --key`     | Delete `--create` flag from `update`. Adding keys is always `addkey`                                                                 |
| `show` shows keys ≈ new `list keys` | `showkey` = full detail view (GSM refs, versions, expiry). `list keys` = compact table. Not true duplication — different granularity |
| `validate` ≈ `check`                | Merge into `check`. `validate` becomes `check metadata`. `validate --cluster` → `check cluster`. `validate --gsm` → `check gsm`      |
| `gcp bootstrap` ≈ `setup` (step 2)  | `setup` already calls `executeGCPBootstrap()`. Keep `gcp bootstrap` as hidden advanced command for standalone GCP re-provisioning    |

---

## Help Output

### Primary: `waxseal --help`

```
waxseal — GitOps-friendly SealedSecrets management with GSM as source of truth

Source of truth:
  - All plaintext secret values live in Google Secret Manager (GSM)
  - Git stores SealedSecret manifests (ciphertext) and metadata

Key Management:
  edit                 Interactively add/update/retire keys
  rotate               Rotate key values (generated or prompted)

Operations:
  reseal               Re-encrypt manifests with current certificate
  check                Health checks (cert, expiry, metadata, gsm, cluster)

Metadata:
  meta list secrets    List registered secrets
  meta list keys       List keys within a secret
  meta showkey         Display detailed secret metadata

Installation:
  setup                First-time setup wizard

Advanced:
  help advanced        Show advanced commands

Flags:
      --config string   Path to waxseal config file (default ".waxseal/config.yaml")
      --dry-run         Show what would be done without making changes
      --repo string     Path to the GitOps repository (default ".")
      --yes             Skip confirmation prompts
  -h, --help            Help for waxseal
  -v, --version         Version for waxseal

Use "waxseal [command] --help" for more information about a command.
```

### Advanced: `waxseal help advanced`

```
Advanced commands for automation, troubleshooting, and infrastructure.
For daily operations, see "waxseal --help".

Key Management (non-interactive / CI):
  addkey               Add a key to a secret (or create a new secret)
  updatekey            Update an existing key's value
  retirekey            Mark a key as retired

Health Checks (individual):
  check cert           Certificate health only
  check expiry         Secret expiration only
  check metadata       Config/schema/hygiene validation
  check gsm            Verify GSM secret versions exist
  check cluster        Compare metadata vs live cluster keys

Discovery & Bootstrap:
  discover             Scan repo for SealedSecret manifests and register them
  gsm bootstrap        Push discovered secrets from cluster to GSM
  gcp bootstrap        Provision GCP project, APIs, and service account

Reminders:
  reminders sync       Create/update reminders for expiring secrets
  reminders list       List upcoming expirations
  reminders clear      Remove reminders for a secret
  reminders setup      Configure reminder settings

Use "waxseal [command] --help" for more information about a command.
```

---

## Command Hierarchy (Final)

```
waxseal
├── edit                          # Interactive wizard (TUI)
│   ├── addkey                    #   → add key flow
│   ├── updatekey                 #   → update key flow
│   └── retirekey                 #   → retire key flow
│
├── rotate [shortName] [keyName]  # Rotate values
├── reseal [shortName|--all]      # Re-encrypt manifests
│
├── check                         # ALL health checks
│   ├── cert                      #   Certificate expiry
│   ├── expiry                    #   Secret expiration dates
│   ├── metadata                  #   Schema, config, hygiene
│   ├── gsm                       #   GSM version existence
│   └── cluster                   #   Metadata vs cluster drift
│
├── meta                          # Metadata operations
│   ├── list                      #
│   │   ├── secrets               #   Table of registered secrets
│   │   └── keys <shortName>      #   Table of keys in a secret
│   └── showkey <shortName>       #   Full metadata detail
│
├── setup                         # First-time setup wizard
│
│ ── (Advanced — hidden from primary help) ──
│
├── addkey <shortName> --key <k>  # Non-interactive add
├── updatekey <shortName> <key>   # Non-interactive update
├── retirekey <shortName>         # Non-interactive retire
├── discover                      # Scan repo for manifests
├── gsm                           #
│   └── bootstrap [shortName]     #   Push cluster → GSM
├── gcp                           #
│   └── bootstrap                 #   Provision GCP infra
├── reminders                     #
│   ├── sync                      #
│   ├── list                      #
│   ├── clear <shortName>         #
│   └── setup                     #
├── help advanced                 # Shows advanced help
└── completion (hidden)           # Shell autocompletion
```

---

## Implementation Order

- [x] 1. Restructure `check`: merge `certcheck.go` + `validate.go` into subcommands under `check`
- [x] 2. Create `meta` parent, move `list` → `meta list secrets`, `show` → `meta showkey`, add `meta list keys`
- [x] 3. Rename `add` → `addkey`, `update` → `updatekey`, `retire` → `retirekey`
- [x] 4. Move `bootstrap` → `gsm bootstrap`
- [x] 5. Hide advanced commands, `completion` from primary help
- [x] 6. Create `help advanced` command
- [x] 7. Create `edit` interactive wizard
- [x] 8. ~~Refactor `addkey`: support adding key to existing secret~~ — `edit` delegates to addkey directly
- [x] 9. ~~Refactor `updatekey`: remove `--create` flag~~ — flag doesn't exist, no-op
- [x] 10. Update root.go help template for grouped sections
- [x] 11. Update all tests (unit + E2E)
- [x] 12. Update AGENTS.md
- [x] 13. Simplify `reseal` (default=all, auto cert check, remove --new-cert)
- [x] 14. Fix `golang.org/x/oauth2` lint (go mod tidy)
