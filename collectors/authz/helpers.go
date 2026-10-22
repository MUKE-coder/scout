package authz

import (
	"context"
	"strings"

	"github.com/MUKE-coder/scout/collectors/crawl"
	"github.com/MUKE-coder/scout/core"
)

// crawlResult is the subset of crawl.Result the access-control checks use.
// A local type lets tests supply fixed pages/endpoints/forms without an HTTP
// crawl.
type crawlResult struct {
	Pages     []string
	Endpoints []string
	Forms     []crawl.Form
}

// crawlFn discovers targets for a scan. It defaults to the real crawler and is
// overridable in tests (a package var, not a field).
var crawlFn = func(ctx context.Context, t core.Target) (*crawlResult, error) {
	res, err := crawl.Crawl(ctx, t)
	if err != nil {
		return nil, err
	}
	return &crawlResult{Pages: res.Pages, Endpoints: res.Endpoints, Forms: res.Forms}, nil
}

// discover runs the crawl for a target, returning nil for a URL-less target.
func discover(ctx context.Context, t core.Target) (*crawlResult, error) {
	if t.URL == "" {
		return nil, nil
	}
	return crawlFn(ctx, t)
}

// exposure maps a target to the exposure of findings on it.
func exposure(t core.Target) core.Exposure {
	if t.IsLocal() {
		return core.ExposureInternal
	}
	return core.ExposureInternet
}

// contains is a case-sensitive substring check.
func contains(hay, needle string) bool { return strings.Contains(hay, needle) }
