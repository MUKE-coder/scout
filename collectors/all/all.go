// Package all blank-imports every built-in collector so their init()
// functions register their checks into core.DefaultRegistry. Import this
// package (for side effects) anywhere the full check set should be active:
//
//	import _ "github.com/MUKE-coder/scout/collectors/all"
//
// The scout CLI already imports it, so `scout scan`, `scout ci` and
// `scout serve` get every collector. Library users who call scout.Mount and
// want checks should add the same blank import to their program.
//
// To add a collector: create its package under collectors/, then add one
// blank-import line below. Nothing else needs to change — scoring, the
// dashboard, SARIF and the compliance view pick it up automatically.
package all

// Collectors register here as they are implemented. Keep the list sorted.
//
// Note on authz: only its implemented checks (auth.jwt, auth.missing,
// auth.cors) register; auth.idor and auth.mass-assignment stay dormant until
// Scout has a test-identity config surface (see collectors/authz).
import (
	_ "github.com/MUKE-coder/scout/collectors/authz"
	_ "github.com/MUKE-coder/scout/collectors/config"
	_ "github.com/MUKE-coder/scout/collectors/crawl"
	_ "github.com/MUKE-coder/scout/collectors/dast"
	_ "github.com/MUKE-coder/scout/collectors/dns"
	_ "github.com/MUKE-coder/scout/collectors/dockerfile"
	_ "github.com/MUKE-coder/scout/collectors/exposure"
	_ "github.com/MUKE-coder/scout/collectors/headers"
	_ "github.com/MUKE-coder/scout/collectors/ports"
	_ "github.com/MUKE-coder/scout/collectors/secrets"
	_ "github.com/MUKE-coder/scout/collectors/tls"
)
