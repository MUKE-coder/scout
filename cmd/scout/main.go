// Command scout is the Scout CLI.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/MUKE-coder/scout/cli"
)

func main() {
	if err := cli.NewRootCmd().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "scout:", err)
		os.Exit(1)
	}
}
