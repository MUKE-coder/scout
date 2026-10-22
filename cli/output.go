package cli

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// useColor decides whether to emit ANSI color: --color=always|never wins;
// auto colors only a terminal and honors NO_COLOR (https://no-color.org).
func useColor(cmd *cobra.Command) bool {
	mode, _ := cmd.Flags().GetString("color")
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := cmd.OutOrStdout().(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) // #nosec G115 -- file descriptors fit in int
}
