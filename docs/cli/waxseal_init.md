## waxseal init

Write .waxseal/config.yaml for this repository

### Synopsis

Create the waxseal configuration: the GCP project that holds the secrets
and where the sealed-secrets controller runs. Nothing else is touched;
fetch the certificate with `waxseal cert fetch` and register
manifests with `waxseal import`.

```
waxseal init [flags]
```

### Options

```
      --controller-name string        service name of the sealed-secrets controller (default "sealed-secrets")
      --controller-namespace string   namespace of the sealed-secrets controller (default "kube-system")
      --force                         overwrite an existing config
  -h, --help                          help for init
      --project string                GCP project ID
```

### Options inherited from parent commands

```
      --dry-run         show what would change without changing anything
      --no-color        disable colour
      --no-input        never prompt; fail if an input is missing
  -o, --output string   output format: text or json (default "text")
      --repo string     path to the repository (default ".")
      --verbose         log subprocess calls and debug detail to stderr
  -y, --yes             answer yes to confirmations
```

### SEE ALSO

* [waxseal](waxseal.md)	 - Manage SealedSecrets with Google Secret Manager as the source of truth

