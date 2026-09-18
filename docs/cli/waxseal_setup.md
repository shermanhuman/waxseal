## waxseal setup

Guided first-time setup (interactive)

### Synopsis

Walk through first-time setup on a terminal: init, optionally provision
GCP, fetch the certificate, discover manifests, import them, and configure
reminders. Each step is an ordinary command; this only sequences them and
asks for what is missing. In scripts, run the steps directly.

```
waxseal setup [flags]
```

### Options

```
  -h, --help   help for setup
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

