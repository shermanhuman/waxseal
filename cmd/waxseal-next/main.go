// waxseal-next is the rewritten CLI, built alongside the old one until the
// swap. It becomes cmd/waxseal.
package main

import (
	"context"
	"os"

	"github.com/shermanhuman/waxseal/internal/cli2"
)

func main() {
	os.Exit(cli2.Main(context.Background(), cli2.NewApp(), os.Args[1:]))
}
