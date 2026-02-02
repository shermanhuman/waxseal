package main

import (
	"os"

	"github.com/shermanhuman/waxseal/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
