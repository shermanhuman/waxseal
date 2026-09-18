## waxseal reseal

Re-encrypt manifests from Secret Manager

### Synopsis

Fetch every key's value from Secret Manager and re-encrypt the manifest.
With no secrets named, every active secret is resealed.

Before sealing, the controller's current certificate is compared with the
one in the repo; a rotated certificate is stored (after confirmation) so
the new ciphertext matches the cluster. --skip-cert-check uses the repo
certificate as is, for CI without cluster access.

Exit 1 when any secret failed.

```
waxseal reseal [secret]... [flags]
```

### Options

```
  -h, --help              help for reseal
      --skip-cert-check   do not compare the repo certificate with the controller's
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

