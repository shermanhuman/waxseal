## waxseal secret retire

Mark a secret retired; optionally delete its manifest

### Synopsis

Mark a secret retired. Retired secrets are skipped by reseal, rotate and
checks. Secret Manager entries are left untouched. Pass --delete-manifest
once nothing consumes the secret any more.

```
waxseal secret retire [secret] [flags]
```

### Options

```
      --delete-manifest      also delete the SealedSecret manifest
  -h, --help                 help for retire
      --reason string        why the secret is retired
      --replaced-by string   short name of the secret that replaces it
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

* [waxseal secret](waxseal_secret.md)	 - List, inspect and retire secrets

