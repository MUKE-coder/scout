package core

import (
	"context"
	"errors"
	"net/http"
)

// ErrNoGuardedClient is returned for requests made outside a scan, where no
// guarded client is attached to the context.
var ErrNoGuardedClient = errors.New("scout: no guarded HTTP client in context; requests must go through the engine")

type httpClientKey struct{}

// WithHTTPClient attaches the scan's guarded client to ctx. The engine calls
// this; checks never construct their own clients.
func WithHTTPClient(ctx context.Context, c *http.Client) context.Context {
	return context.WithValue(ctx, httpClientKey{}, c)
}

// HTTPClient returns the guarded client for this scan. Checks must use it
// for every outbound request: it enforces scope, rate limits, scan windows
// and the kill switch, and signs requests as Scout self-tests.
//
// Outside a scan it returns a client that refuses every request, so a check
// can never send unguarded traffic by accident.
func HTTPClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(httpClientKey{}).(*http.Client); ok && c != nil {
		return c
	}
	return refusingClient
}

var refusingClient = &http.Client{Transport: refuseTransport{}}

type refuseTransport struct{}

func (refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrNoGuardedClient
}
