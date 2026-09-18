## waxseal rotate

Generate new values for generated keys and reseal them

### Synopsis

Generate a new value for each generated key, store it as a new Secret
Manager version and re-encrypt the manifest. With no keys named, every
generated key of the secret is rotated and the others are listed as
skipped. Keys rotated elsewhere get their new value with `waxseal key set`.

```
waxseal rotate [secret] [key]... [flags]
```

### Options

```
  -h, --help   help for rotate
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

