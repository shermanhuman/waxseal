# Changelog

## 0.6.0 (unreleased)

### Added

- `key add --from-key <secret>/<key>` copies a value waxseal already
  manages into a new key, in any namespace, without the value leaving
  waxseal. The source's pinned Secret Manager version goes into the new
  key's own Secret Manager secret, and its kind, template, rotation mode
  and expiry come with it. A new secret takes the source secret's type
  unless `--type` is given. `--dry-run` shows the source and version.
- The copy is recorded in metadata as `copiedFrom` and shown by
  `secret show`. `key set --from-key` re-copies the source's current
  value.
- When `key set` or `rotate` gives a key a new value, Next lists the
  command that re-copies each of its copies. `check metadata` warns when a
  copy is behind its source.
- `check metadata` warns when keys sharing one Secret Manager secret pin
  different versions of it.

### Fixed

- `--generate` works with every `--rotation` mode, so
  `--template 'v1:{{secret}}' --generate --rotation static` makes a
  fixed-shape value (such as a keyring entry) that `rotate` will not
  replace. A generator is recorded only for `generated` keys, and
  `--generator` defaults to `randomBase64`.
- `key add --rotation generated --from-file …` stores the given value and
  keeps the generator for later rotations; it used to fail asking for a
  value.
- Conflicting value flags (for example `--from-file` with `--generate`)
  exit 2 (usage) instead of 1.
- `key add` refuses a key whose Secret Manager secret another registered
  key already uses. Names map to `<secret>-<key>`, so `a-b`/`c` and
  `a`/`b-c` collide; the second add used to add a version to the first
  key's secret, silently sharing it.

### Upgrading

Metadata with `copiedFrom` cannot be read by waxseal 0.5, which rejects
unknown fields. Upgrade every machine and CI job that runs waxseal on a
repository before using `--from-key` in it.

## 0.5.0 (2026-09-18)

A ground-up rewrite. Every command can be driven entirely by flags; on a
terminal, waxseal prompts for whatever you leave out; with `--no-input` or
in CI it fails instead, naming the missing flag. The command tree is new
and there are no aliases for the old names. On-disk formats are
unchanged: existing repositories keep working.

### Command mapping

| 0.4 | 0.5 |
|---|---|
| `setup` (wizard) | `init` + `gcp provision` + `cert fetch` + `discover` + `import` + `reminders configure`; `setup` sequences them on a terminal |
| `gsm gcp-bootstrap` | `gcp provision` |
| `gsm bootstrap [secret]` | `import [secret]...` |
| `edit`, `edit addkey/updatekey/retirekey` | removed; every command picks the secret and key on a terminal |
| `addkey <secret> --key ...` | `key add [secret] [key]` (creates the secret on its first key) |
| `updatekey <s> <k> --stdin` | `key set <s> <k> --from-file -` |
| `updatekey --generate-random` | `key set --generate` |
| `updatekey --create` | `key add` |
| `updatekey` computed menu / rotation prompt | `key edit --template/--param/--rotation/--generator/--expires` |
| `retirekey <secret>` | `secret retire [secret]` |
| `rotate <s> [k] --generated` | `rotate [secret] [key]...` (generated keys only) |
| `check <sub>` | `check [cert|expiry|metadata|gsm|cluster]...` |
| `meta list secrets` / `meta list keys` / `meta showkey` | `secret list` / `secret show` |
| `--json`, `--yaml`, `-o` on `meta` | global `-o json` |
| `reminders setup` / `reminders list` | `reminders configure` / `check expiry --warn-days N` |
| `discover --non-interactive` | `discover` (read-only) + global `--no-input` |
| `advanced`, hidden commands | removed; nothing is hidden |
| `--config`, `--kubeconfig` | removed (`kubectl` honours `$KUBECONFIG`) |

### Behaviour changes

- `rotate` acts on generated keys only. A key rotated elsewhere gets its
  new value with `key set`; `--yes` can no longer skip a rotation
  silently.
- `discover` writes nothing; `import` reads the cluster secret, stores it
  in Secret Manager and writes metadata, so metadata never carries a
  placeholder version.
- Secret values are read from `--from-file` (or `-` for stdin),
  generated, or typed at a masked prompt; never taken from the command
  line.
- `check` reports findings (also as JSON) and exits 1 on errors, 2 on
  warnings with `--fail-on-warning`. It now also detects manifest scope
  and key-set drift from metadata. The internal-hostname warning is gone.
- `reseal` compares the repo certificate with the controller's and asks
  before adopting a rotated one (`--skip-cert-check` for CI).
- `state.yaml` is no longer written (it was never read). Existing files
  are left alone.
- Metadata files may be re-quoted on their next write; content is
  unchanged. Comments in metadata and config do not survive a write.
- Config fields no command read (`discovery`, `bootstrap`,
  `store.defaultReplication`, `store.labels`, `controller.keySecretLabel`,
  `cert.verifyAgainstCluster`, `reminders.eventTitleTemplate`,
  `reminders.auth`) are accepted on read and dropped on write.
  `reminders.auth` is no longer required.

### Fixes

- Namespace-wide and cluster-wide manifests were read back as strict, so
  updating one re-sealed it with the wrong label.
- Cross-secret computed inputs lost their `shortName` on write, and a
  retire reason containing `: ` produced an unparseable metadata file.
- `rotate` wrote metadata non-atomically right after creating the GSM
  version, and printed the start of rendered connection strings.
- The create-secret rollback did not run on sealing or metadata-write
  failures, and could delete a pre-existing Secret Manager secret.
- Reminders could never be configured on a generated config.
