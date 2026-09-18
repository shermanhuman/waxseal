## waxseal key set

Store a new value for a key and reseal it

### Synopsis

Store a new version of a key's value in Secret Manager and re-encrypt it
into the manifest. For a computed key the value is its {{secret}} part.

The value comes from --from-file (or - for stdin), from --generate for a
key with a generator, or from a masked prompt on a terminal.

```
waxseal key set [secret] [key] [flags]
```

### Options

```
      --expires string     new expiry date (YYYY-MM-DD or RFC 3339), or 'none' to clear
      --from-file string   read the value from a file, or from stdin with -
      --generate           generate a random value
  -h, --help               help for set
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

* [waxseal key](waxseal_key.md)	 - Add keys, set their values and change how they are managed

