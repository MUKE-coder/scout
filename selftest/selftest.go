// Package selftest signs and verifies the X-Scout-Scan header that Scout puts
// on every outbound scan request. Sentinel (or any app) can verify it to tag
// Scout traffic as a self-test rather than a real attacker.
//
// Header format:
//
//	X-Scout-Scan: v1;ts=<unix seconds>;scan=<scan id>;sig=<hex hmac>
//
// The signature is HMAC-SHA256 over the version, timestamp, scan ID, method,
// host and path, so a captured header cannot be replayed against another
// endpoint or reused after the allowed clock skew.
package selftest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header is the self-test header name.
const Header = "X-Scout-Scan"

const version = "v1"

// DefaultMaxSkew is how far a header timestamp may drift from the verifier's clock.
const DefaultMaxSkew = 5 * time.Minute

// Verification errors.
var (
	ErrMissing   = errors.New("selftest: header missing")
	ErrMalformed = errors.New("selftest: header malformed")
	ErrExpired   = errors.New("selftest: timestamp outside allowed skew")
	ErrSignature = errors.New("selftest: signature mismatch")
)

// NewKey returns a random 32-byte signing key.
func NewKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return k
}

func mac(key []byte, ts int64, scanID, method, host, path string) string {
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%s\n%d\n%s\n%s\n%s\n%s", version, ts, scanID, strings.ToUpper(method), strings.ToLower(host), path)
	return hex.EncodeToString(h.Sum(nil))
}

func requestPath(r *http.Request) string {
	if p := r.URL.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// Sign sets the self-test header on r.
func Sign(r *http.Request, key []byte, scanID string, now time.Time) {
	ts := now.Unix()
	sig := mac(key, ts, scanID, r.Method, r.URL.Host, requestPath(r))
	r.Header.Set(Header, fmt.Sprintf("%s;ts=%d;scan=%s;sig=%s", version, ts, scanID, sig))
}

// Info is what a valid header tells the verifier.
type Info struct {
	ScanID string
	Time   time.Time
}

// Verify checks the self-test header on an incoming request. Host is taken
// from r.Host, which is what the signer saw as the URL host.
func Verify(r *http.Request, key []byte, now time.Time, maxSkew time.Duration) (Info, error) {
	raw := r.Header.Get(Header)
	if raw == "" {
		return Info{}, ErrMissing
	}
	parts := strings.Split(raw, ";")
	if len(parts) != 4 || parts[0] != version {
		return Info{}, ErrMalformed
	}
	fields := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok || v == "" {
			return Info{}, ErrMalformed
		}
		fields[k] = v
	}
	ts, err := strconv.ParseInt(fields["ts"], 10, 64)
	if err != nil || fields["scan"] == "" || fields["sig"] == "" {
		return Info{}, ErrMalformed
	}
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	at := time.Unix(ts, 0)
	if d := now.Sub(at); d > maxSkew || d < -maxSkew {
		return Info{}, ErrExpired
	}
	want := mac(key, ts, fields["scan"], r.Method, r.Host, requestPath(r))
	if !hmac.Equal([]byte(want), []byte(fields["sig"])) {
		return Info{}, ErrSignature
	}
	return Info{ScanID: fields["scan"], Time: at}, nil
}

// Transport signs every request it sends. It clones the request so callers'
// requests are never mutated.
type Transport struct {
	Base   http.RoundTripper
	Key    []byte
	ScanID string
	Now    func() time.Time
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	signed := r.Clone(r.Context())
	Sign(signed, t.Key, t.ScanID, now())
	return base.RoundTrip(signed)
}
