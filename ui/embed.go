// Package ui embeds the built dashboard (ui/dist) so consumers never need
// Node. Rebuild it with: cd ui/dashboard && npm ci && npm run build
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built dashboard rooted at its index.html.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the embed directive guarantees dist exists
	}
	return sub
}
