// Package oob provides an out-of-band application security testing (OAST)
// listener: a small HTTP server that Scout points a payload's callback URL at,
// so a *blind* vulnerability — blind SSRF, blind command injection, XXE — is
// confirmed by observing the target call back, correlated by a unique token.
//
// This is detection, not exploitation: Scout only observes the inbound request.
// The listener is Scout's own (no third-party interaction service like
// interactsh), so nothing ever leaves the operator's environment.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Interaction is one inbound request the listener recorded.
type Interaction struct {
	At         time.Time
	RemoteAddr string
	Method     string
	Path       string
	UserAgent  string
}

// Listener is a running OAST HTTP server that records callbacks by token.
type Listener struct {
	base string
	srv  *http.Server
	mu   sync.Mutex
	hits map[string][]Interaction
}

// Start begins an OAST listener. publicBase, when set, is the base URL the target
// can reach back on (e.g. "http://10.0.0.5:9999" or
// "http://host.docker.internal:9999"); the server binds that port on all
// interfaces. When empty, the listener binds an ephemeral 127.0.0.1 port and uses
// it as the callback base — which works when the target runs on the same host.
func Start(_ context.Context, publicBase string) (*Listener, error) {
	l := &Listener{hits: map[string][]Interaction{}}
	addr := "127.0.0.1:0"
	if publicBase != "" {
		u, err := url.Parse(publicBase)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid OOB base %q", publicBase)
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		addr = ":" + port
		l.base = strings.TrimRight(publicBase, "/")
	}
	ln, err := net.Listen("tcp", addr) // #nosec G102 -- an OAST listener must be reachable by the target
	if err != nil {
		return nil, err
	}
	if l.base == "" {
		l.base = "http://" + ln.Addr().String()
	}
	l.srv = &http.Server{Handler: l, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

// ServeHTTP records every inbound request, keyed by the first path segment (the
// correlation token), and answers with a tiny body.
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tok := firstSegment(r.URL.Path); tok != "" {
		l.mu.Lock()
		l.hits[tok] = append(l.hits[tok], Interaction{
			At: time.Now(), RemoteAddr: r.RemoteAddr, Method: r.Method,
			Path: r.URL.Path, UserAgent: r.UserAgent(),
		})
		l.mu.Unlock()
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// URL returns the callback URL that carries a token.
func (l *Listener) URL(token string) string { return l.base + "/" + token }

// Hits returns a copy of the interactions recorded for a token.
func (l *Listener) Hits(token string) []Interaction {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Interaction(nil), l.hits[token]...)
}

// Close shuts the listener down.
func (l *Listener) Close() {
	if l.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = l.srv.Shutdown(ctx)
	}
}

// NewToken returns a random, URL-safe correlation token.
func NewToken() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return "scout" + hex.EncodeToString(b[:])
}

func firstSegment(p string) string {
	p = strings.TrimLeft(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return p
}
