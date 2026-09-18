## waxseal completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(waxseal completion bash)

To load completions for every new session, execute once:

#### Linux:

	waxseal completion bash > /etc/bash_completion.d/waxseal

#### macOS:

	waxseal completion bash > $(brew --prefix)/etc/bash_completion.d/waxseal

You will need to start a new shell for this setup to take effect.


```
waxseal completion bash
```

### Options

```
  -h, --help              help for bash
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

