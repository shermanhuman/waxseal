## waxseal completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(waxseal completion zsh)

To load completions for every new session, execute once:

#### Linux:

	waxseal completion zsh > "${fpath[1]}/_waxseal"

#### macOS:

	waxseal completion zsh > $(brew --prefix)/share/zsh/site-functions/_waxseal

You will need to start a new shell for this setup to take effect.


```
waxseal completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

