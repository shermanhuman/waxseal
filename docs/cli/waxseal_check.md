## waxseal check

Check certificate, expiry, metadata, GSM and cluster state

### Synopsis

Run health checks. With no arguments every check runs, and the ones that
need GSM credentials or cluster access are skipped when those are absent.
Naming a check makes it mandatory.

Exit codes: 0 healthy, 1 errors found, 2 warnings found with --fail-on-warning.

```
waxseal check [cert|expiry|metadata|gsm|cluster]... [flags]
```

### Options

```
      --fail-on-warning   exit 2 when there are warnings
  -h, --help              help for check
      --warn-days int     warn when a certificate or key expires within this many days (default 30)
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

