package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// WellKnownPath is where a target can publish its ownership token.
const WellKnownPath = "/.well-known/scout-verify.txt"

// TXTPrefix prefixes the token in a DNS TXT record.
const TXTPrefix = "scout-verify="

// ErrNotVerified means no ownership proof was found for a host.
var ErrNotVerified = errors.New("ownership not verified")

// Resolver looks up DNS TXT records. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// OwnershipToken is the token a host must publish to prove its owner wants
// it scanned. With a key it is an HMAC unique to this Scout installation;
// without one it is a plain hash of the host.
func OwnershipToken(key []byte, host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(key) == 0 {
		sum := sha256.Sum256([]byte("scout-verify:" + host))
		return hex.EncodeToString(sum[:16])
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("scout-verify:" + host))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Verifier checks target ownership by DNS TXT record or well-known file and
// caches successes.
type Verifier struct {
	Key      []byte
	Resolver Resolver
	// TTL is how long a successful verification is cached.
	TTL time.Duration
	Now func() time.Time

	mu       sync.Mutex
	verified map[string]time.Time
}

// NewVerifier returns a verifier using the system DNS resolver.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{Key: key, Resolver: net.DefaultResolver, TTL: time.Hour, Now: time.Now}
}

// Verify proves ownership of t's host. It returns how it was proven
// ("local", "dns", "well-known", "cached"). The HTTP check uses client,
// which must be the scan's guarded client.
func (v *Verifier) Verify(ctx context.Context, t core.Target, client *http.Client) (string, error) {
	if t.IsLocal() {
		return "local", nil
	}
	host := strings.ToLower(t.Host())
	if host == "" {
		return "", fmt.Errorf("%w: target has no host", ErrNotVerified)
	}
	now := v.now()
	v.mu.Lock()
	if at, ok := v.verified[host]; ok && now.Sub(at) < v.TTL {
		v.mu.Unlock()
		return "cached", nil
	}
	v.mu.Unlock()

	token := OwnershipToken(v.Key, host)
	method := ""
	switch {
	case v.checkDNS(ctx, host, token):
		method = "dns"
	case v.checkWellKnown(ctx, t, token, client):
		method = "well-known"
	default:
		return "", fmt.Errorf("%w for %s: publish TXT %q on %s or _scout-verify.%s, or serve it at %s",
			ErrNotVerified, host, TXTPrefix+token, host, host, WellKnownPath)
	}

	v.mu.Lock()
	if v.verified == nil {
		v.verified = make(map[string]time.Time)
	}
	v.verified[host] = now
	v.mu.Unlock()
	return method, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) checkDNS(ctx context.Context, host, token string) bool {
	if v.Resolver == nil {
		return false
	}
	for _, name := range []string{"_scout-verify." + host, host} {
		records, err := v.Resolver.LookupTXT(ctx, name)
		if err != nil {
			continue
		}
		for _, r := range records {
			if strings.TrimSpace(r) == TXTPrefix+token {
				return true
			}
		}
	}
	return false
}

func (v *Verifier) checkWellKnown(ctx context.Context, t core.Target, token string, client *http.Client) bool {
	if client == nil {
		return false
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return false
	}
	wellKnown := url.URL{Scheme: u.Scheme, Host: u.Host, Path: WellKnownPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown.String(), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if l := strings.TrimSpace(line); l == token || l == TXTPrefix+token {
			return true
		}
	}
	return false
}
