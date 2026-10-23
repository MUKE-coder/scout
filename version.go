package scout

import "runtime/debug"

// buildVersion is stamped at release-build time with
//
//	-ldflags "-X github.com/MUKE-coder/scout.buildVersion=v1.2.3"
//
// (GoReleaser does this; see .goreleaser.yaml). It is empty for a plain
// `go build`/`go run` from a checkout.
var buildVersion string

// Version is the Scout version, resolved once at startup. Resolution order:
//  1. the release ldflags stamp (buildVersion), when present;
//  2. the module version recorded in the binary by `go install module@vX`;
//  3. a dev marker for a local checkout build.
var Version = resolveVersion()

func resolveVersion() string {
	if buildVersion != "" {
		return buildVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "0.0.0-dev"
}
