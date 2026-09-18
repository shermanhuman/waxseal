## waxseal key

Add keys, set their values and change how they are managed

### Options

```
  -h, --help   help for key
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
* [waxseal key add](waxseal_key_add.md)	 - Add a key; creates the secret if it does not exist
* [waxseal key edit](waxseal_key_edit.md)	 - Change how a key is managed: rotation, generator, expiry, template
* [waxseal key set](waxseal_key_set.md)	 - Store a new value for a key and reseal it

