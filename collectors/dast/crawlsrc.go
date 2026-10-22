package dast

import (
	"context"

	"github.com/MUKE-coder/scout/collectors/crawl"
	"github.com/MUKE-coder/scout/core"
)

// crawlResult is the subset of crawl.Result the DAST probes consume. Using a
// local type lets tests supply a fixed set of pages/endpoints without standing
// up an HTTP crawl.
type crawlResult struct {
	Pages     []string
	Endpoints []string
}

// crawlFn discovers targets for a scan. It defaults to the real crawler and is
// overridable in tests. It is a package var, not a field, so the zero-value
// check structs keep working.
var crawlFn = func(ctx context.Context, t core.Target) (*crawlResult, error) {
	res, err := crawl.Crawl(ctx, t)
	if err != nil {
		return nil, err
	}
	return &crawlResult{Pages: res.Pages, Endpoints: res.Endpoints}, nil
}

// discover runs the crawl for a target, returning nil for a URL-less target.
func discover(ctx context.Context, t core.Target) (*crawlResult, error) {
	if t.URL == "" {
		return nil, nil
	}
	return crawlFn(ctx, t)
}
