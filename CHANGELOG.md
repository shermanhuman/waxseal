# Changelog

## 0.5.0 (unreleased)

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
