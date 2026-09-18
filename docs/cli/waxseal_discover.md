## waxseal discover

Find SealedSecret manifests in the repository

### Synopsis

Walk the repository for SealedSecret manifests and report which ones
metadata already covers. Nothing is written; register new manifests with
`waxseal import`, which reads their plaintext from the cluster.

```
waxseal discover [flags]
```

### Options

```
  -h, --help   help for discover
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

