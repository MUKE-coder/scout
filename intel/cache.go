package intel

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// cacheDir is where Scout stores its on-disk intelligence snapshots (KEV
// catalog, EPSS scores). It is the user cache dir, so it survives between runs
// and lets scans work offline after the first fetch. Overridable for tests.
var cacheDir = defaultCacheDir

func defaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "scout", "intel")
	_ = os.MkdirAll(dir, 0o750)
	return dir
}

// snapshot is the result of a cached fetch: the bytes plus when they were
// retrieved (the file's mtime), for provenance.
type snapshot struct {
	Data      []byte
	Retrieved time.Time
	FromCache bool
}

// cachedFetch returns name's contents from the on-disk cache when the cached
// copy is younger than ttl. Otherwise it fetches url, writes the snapshot, and
// returns it. If the fetch fails but a stale cache copy exists, that copy is
// returned (offline resilience) — a stale snapshot beats no data.
func cachedFetch(ctx context.Context, client *http.Client, name, url string, ttl time.Duration) (snapshot, error) {
	path := filepath.Join(cacheDir(), name)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < ttl {
		if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed cache dir, fixed name
			return snapshot{Data: b, Retrieved: fi.ModTime(), FromCache: true}, nil
		}
	}

	b, err := fetch(ctx, client, url)
	if err != nil {
		// Fall back to a stale copy if we have one.
		if sb, serr := os.ReadFile(path); serr == nil { // #nosec G304 -- fixed cache dir, fixed name
			fi, _ := os.Stat(path)
			t := time.Time{}
			if fi != nil {
				t = fi.ModTime()
			}
			return snapshot{Data: sb, Retrieved: t, FromCache: true}, nil
		}
		return snapshot{}, err
	}
	_ = os.WriteFile(path, b, 0o600)
	return snapshot{Data: b, Retrieved: time.Now(), FromCache: false}, nil
}

// readCacheFile returns the raw bytes of a cached file, or nil if absent.
func readCacheFile(name string) []byte {
	b, err := os.ReadFile(filepath.Join(cacheDir(), name)) // #nosec G304 -- fixed cache dir, fixed name
	if err != nil {
		return nil
	}
	return b
}

// writeCache writes bytes to a named cache file, best-effort.
func writeCache(name string, b []byte) {
	_ = os.WriteFile(filepath.Join(cacheDir(), name), b, 0o600)
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{url: url, code: resp.StatusCode}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
}

type httpError struct {
	url  string
	code int
}

func (e *httpError) Error() string {
	return "intel: GET " + e.url + " returned status " + itoa(e.code)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
