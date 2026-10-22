// Command scout is the Scout CLI.
//
// Exit codes: 0 success, 1 CI gate failed, 2 error.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/MUKE-coder/scout/cli"

	// Register every built-in collector's checks into the default registry.
	_ "github.com/MUKE-coder/scout/collectors/all"
)

func main() {
	err := cli.NewRootCmd().ExecuteContext(context.Background())
	if err != nil {
		var gate *cli.GateError
		if !errors.As(err, &gate) { // the gate already printed its verdict
			fmt.Fprintln(os.Stderr, "scout:", err)
		}
	}
	os.Exit(cli.ExitCode(err))
}
