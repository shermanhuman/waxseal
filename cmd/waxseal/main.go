// waxseal keeps SealedSecret plaintext in Google Secret Manager and only
// ciphertext in Git.
package main

import (
	"context"
	"os"

	"github.com/shermanhuman/waxseal/internal/cli"
)

func main() {
	os.Exit(cli.Main(context.Background(), cli.NewApp(), os.Args[1:]))
}
