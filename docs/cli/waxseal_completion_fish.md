## waxseal completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	waxseal completion fish | source

To load completions for every new session, execute once:

	waxseal completion fish > ~/.config/fish/completions/waxseal.fish

You will need to start a new shell for this setup to take effect.


```
waxseal completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
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

* [waxseal completion](waxseal_completion.md)	 - Generate the autocompletion script for the specified shell

