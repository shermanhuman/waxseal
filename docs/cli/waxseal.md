## waxseal

Manage SealedSecrets with Google Secret Manager as the source of truth

### Synopsis

waxseal keeps the plaintext of every Kubernetes secret in Google Secret
Manager and only ciphertext in Git. Metadata under .waxseal/ pins each key
to a GSM secret and version, so manifests can be re-sealed at any time.

Every command can be driven entirely by flags. On a terminal, waxseal
prompts for whatever you leave out; with --no-input or in CI it fails
instead, naming the missing flag.

### Options

```
      --dry-run         show what would change without changing anything
  -h, --help            help for waxseal
      --no-color        disable colour
      --no-input        never prompt; fail if an input is missing
  -o, --output string   output format: text or json (default "text")
      --repo string     path to the repository (default ".")
      --verbose         log subprocess calls and debug detail to stderr
  -y, --yes             answer yes to confirmations
```

### SEE ALSO

* [waxseal cert](waxseal_cert.md)	 - Manage the controller certificate
* [waxseal check](waxseal_check.md)	 - Check certificate, expiry, metadata, GSM and cluster state
* [waxseal completion](waxseal_completion.md)	 - Generate the autocompletion script for the specified shell
* [waxseal discover](waxseal_discover.md)	 - Find SealedSecret manifests in the repository
* [waxseal gcp](waxseal_gcp.md)	 - Provision GCP for waxseal
* [waxseal import](waxseal_import.md)	 - Register manifests by reading their values from the cluster
* [waxseal init](waxseal_init.md)	 - Write .waxseal/config.yaml for this repository
* [waxseal key](waxseal_key.md)	 - Add keys, set their values and change how they are managed
* [waxseal reminders](waxseal_reminders.md)	 - Expiry reminders in Google Tasks or Calendar
* [waxseal reseal](waxseal_reseal.md)	 - Re-encrypt manifests from Secret Manager
* [waxseal rotate](waxseal_rotate.md)	 - Generate new values for generated keys and reseal them
* [waxseal secret](waxseal_secret.md)	 - List, inspect and retire secrets
* [waxseal setup](waxseal_setup.md)	 - Guided first-time setup (interactive)

