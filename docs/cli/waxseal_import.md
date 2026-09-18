## waxseal import

Register manifests by reading their values from the cluster

### Synopsis

Read each secret's plaintext from the cluster, store it in Secret Manager
and write metadata for it. Names are the ones `waxseal discover` suggests,
or registered secrets to re-import. Connection strings become computed
keys with the password as their {{secret}}. Every key is registered as
externally rotated; change that with `waxseal key edit`.

```
waxseal import [secret]... [flags]
```

### Options

```
  -h, --help   help for import
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

