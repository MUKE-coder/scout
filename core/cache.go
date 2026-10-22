package core

import (
	"context"
	"sync"
)

type scanCacheKey struct{}

// ScanCache memoizes expensive lookups (page fetches, TLS handshakes, DNS)
// within one scan so checks that need the same data share a single request.
type ScanCache struct {
	m sync.Map // key -> *cacheEntry
}

type cacheEntry struct {
	once sync.Once
	val  any
	err  error
}

// WithScanCache attaches a fresh cache to ctx. The engine does this per scan.
func WithScanCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, scanCacheKey{}, &ScanCache{})
}

// Memo returns the cached value for key, computing it with fn exactly once
// per scan even when called concurrently. Without a cache in ctx, fn runs
// every time.
func Memo[T any](ctx context.Context, key string, fn func() (T, error)) (T, error) {
	c, _ := ctx.Value(scanCacheKey{}).(*ScanCache)
	if c == nil {
		return fn()
	}
	v, _ := c.m.LoadOrStore(key, &cacheEntry{})
	e := v.(*cacheEntry)
	e.once.Do(func() { e.val, e.err = fn() })
	val, _ := e.val.(T)
	return val, e.err
}
