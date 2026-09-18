# WaxSeal

![waxseal-logo](https://github.com/user-attachments/assets/a914aa45-7945-429e-ac22-723654557e4e)

> SealedSecrets for GitOps, with Google Secret Manager as the source of truth.

waxseal keeps the plaintext of every Kubernetes secret in Google Secret
Manager (GSM) and only ciphertext in Git. Metadata under `.waxseal/` pins
each key to a GSM secret and version, so manifests can be re-encrypted at
any time: after a controller certificate rotation, after a value changes,
or to rebuild a repository from scratch.

Every command can be driven entirely by flags. On a terminal, waxseal
prompts for whatever you leave out; with `--no-input` or in CI it fails
instead, naming the missing flag.

## Install

```sh
go install github.com/shermanhuman/waxseal/cmd/waxseal@latest
```

Or download a release from the
[releases page](https://github.com/shermanhuman/waxseal/releases).

You also need `gcloud` (authenticated with
`gcloud auth application-default login`), `kubeseal`, and `kubectl`
pointed at a cluster running the
[sealed-secrets controller](https://github.com/bitnami-labs/sealed-secrets).

## Five-minute start

```sh
cd my-gitops-repo

# 1. Point waxseal at the GCP project that holds the values.
waxseal init --project my-gcp-project

# 2. Enable Secret Manager and create the service account (once per project).
waxseal gcp provision --project my-gcp-project

# 3. Store the controller's certificate in the repo.
waxseal cert fetch

# 4. Register the SealedSecret manifests you already have.
waxseal discover          # lists them and whether metadata covers them
waxseal import            # reads their values from the cluster into GSM

# 5. Or add a brand-new secret.
echo -n 'hunter2' | waxseal key add my-app db_password --namespace prod --rotation external --from-file -
waxseal key add my-app api_token --generate

git add .waxseal keys apps && git commit -m "Manage secrets with waxseal"
```

On a terminal, `waxseal setup` walks through the same steps.

## Day to day

```sh
waxseal secret list                        # what is managed
waxseal secret show my-app                 # keys, where their values live, expiry

waxseal key set my-app db_password --from-file -    # a value changed elsewhere
waxseal rotate my-app                      # new values for every generated key
waxseal key edit my-app api_token --expires 2027-01-01

waxseal reseal                             # re-encrypt everything (detects a rotated certificate)
waxseal check                              # cert, expiry, metadata, GSM, cluster
waxseal secret retire old-app --replaced-by new-app --delete-manifest
```

Add `--dry-run` to any command that changes something to see what it would
do, and `-o json` to any command for machine-readable output.

## Commands

| Command | What it does |
|---|---|
| `secret list`, `secret show`, `secret retire` | inspect and retire secrets |
| `key add`, `key set`, `key edit` | add a key (creating the secret if needed), store a new value, change rotation/expiry/template |
| `rotate` | generate new values for generated keys and reseal |
| `reseal` | re-encrypt manifests from GSM; adopts a rotated controller certificate |
| `check` | health checks; exit 1 on errors, 2 on warnings with `--fail-on-warning` |
| `reminders sync`, `reminders clear`, `reminders configure` | expiry reminders in Google Tasks or Calendar |
| `init`, `gcp provision`, `cert fetch`, `discover`, `import`, `setup` | first-time setup |

Global flags: `--repo`, `--dry-run`, `-y/--yes` (accept confirmations),
`--no-input` (never prompt), `-o text|json`, `--no-color`, `--verbose`.

The full reference is in [docs/cli](docs/cli/waxseal.md) and in
`waxseal <command> --help`.

### Where a value comes from

Secret values are never taken from the command line. `key add` and
`key set` read them from `--from-file PATH` (or `-` for stdin), generate
them with `--generate`, or ask at a masked prompt on a terminal. One
trailing newline is stripped, so `echo` works as expected.

### Rotation modes

| Mode | Meaning |
|---|---|
| `generated` | waxseal generates a new value on `rotate` (`randomBase64` or `randomHex`, `--bytes N`) |
| `external` | rotated at a vendor; give waxseal the new value with `key set` |
| `static` | not expected to change |
| `unknown` | not decided yet |

### Computed keys

A computed key is rendered from a template whose `{{secret}}` part is the
rotatable value, for example a `DATABASE_URL`:

```sh
waxseal key add my-app DATABASE_URL --generate \
  --template 'postgresql://app:{{secret}}@{{host}}:{{port}}/{{database}}' \
  --param host=db.internal --param port=5432 --param database=app
waxseal key edit my-app DATABASE_URL --param host=db2.internal   # change a value
waxseal rotate my-app DATABASE_URL                              # new password, re-rendered
```

`import` recognises connection strings in cluster secrets and turns them
into computed keys automatically.

## Files in the repository

```
.waxseal/config.yaml           project, controller location, reminders
.waxseal/metadata/<name>.yaml  one file per secret: keys, GSM references, rotation, expiry
keys/pub-cert.pem              the controller's sealing certificate
apps/<name>/sealed-secret.yaml the SealedSecret manifest (path is configurable per secret)
```

Metadata for a secret looks like this:

```yaml
shortName: my-app
manifestPath: apps/my-app/sealed-secret.yaml
sealedSecret:
  name: my-app
  namespace: prod
  scope: strict
status: active
keys:
  - keyName: db_password
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-gcp-project/secrets/my-app-db_password
      version: "3"
    rotation:
      mode: external
    expiry:
      expiresAt: "2027-01-01T00:00:00Z"
  - keyName: api_token
    source:
      kind: gsm
    gsm:
      secretResource: projects/my-gcp-project/secrets/my-app-api_token
      version: "1"
    rotation:
      mode: generated
      generator:
        kind: randomBase64
        bytes: 32
```

waxseal owns these files: it rewrites them whole, and comments do not
survive a write.

## CI

```yaml
- run: waxseal check --fail-on-warning --warn-days 30
- run: waxseal reseal --skip-cert-check --no-input
  env:
    GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_SA_KEY }}
```

`waxseal gcp provision --github-repo owner/repo` sets up Workload Identity
so Actions can authenticate without a key file.

## Security

- No plaintext on disk. Results, logs and error messages never carry
  values.
- GSM versions are pinned numerically; `latest` is rejected.
- Every file waxseal writes is validated first and written atomically.
- Encryption is delegated to `kubeseal`, so ciphertext is exactly what the
  controller expects.
- Authentication is Application Default Credentials; nothing is stored in
  the repository.

Required IAM: `roles/secretmanager.secretAccessor` to reseal;
`roles/secretmanager.secretVersionAdder` (plus create/delete for new
secrets) to add keys, set values and rotate.

## Development

See [ARCHITECTURE.md](ARCHITECTURE.md) for the package layout and the
rules CI enforces, and [AGENTS.md](AGENTS.md) for the commands.

## License

[MIT](LICENSE)
