## waxseal reminders configure

Enable reminders and choose where they go

```
waxseal reminders configure [flags]
```

### Options

```
      --calendar string    Google Calendar ID (default "primary")
  -h, --help               help for configure
      --lead-days string   days before expiry to remind, comma-separated (default "30,7,1")
      --provider string    where reminders are created (tasks|calendar|both|none)
      --tasklist string    Google Tasks list ID (default "@default")
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

* [waxseal reminders](waxseal_reminders.md)	 - Expiry reminders in Google Tasks or Calendar

