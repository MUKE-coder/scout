package storage

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// DefaultMemoryCapacity is how many scans the memory store keeps.
const DefaultMemoryCapacity = 100

// Memory is a fixed-size ring buffer of scans. When full, the oldest scan is
// overwritten. It is the hot-path store and the fallback with no DB.
type Memory struct {
	mu    sync.RWMutex
	buf   []core.ScanResult
	next  int // slot the next new scan goes into
	count int
}

// NewMemory returns a ring buffer holding up to capacity scans.
func NewMemory(capacity int) *Memory {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	return &Memory{buf: make([]core.ScanResult, capacity)}
}

// ordered returns scans newest first. Caller holds at least a read lock.
func (m *Memory) ordered() []core.ScanResult {
	out := make([]core.ScanResult, 0, m.count)
	for i := 1; i <= m.count; i++ {
		out = append(out, m.buf[(m.next-i+len(m.buf))%len(m.buf)])
	}
	return out
}

func (m *Memory) SaveScan(_ context.Context, s core.ScanResult) error {
	s = cloneScan(s) // the caller may keep mutating its copy
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 1; i <= m.count; i++ {
		idx := (m.next - i + len(m.buf)) % len(m.buf)
		if m.buf[idx].ID == s.ID {
			m.buf[idx] = s
			return nil
		}
	}
	m.buf[m.next] = s
	m.next = (m.next + 1) % len(m.buf)
	if m.count < len(m.buf) {
		m.count++
	}
	return nil
}

func (m *Memory) GetScan(_ context.Context, id string) (core.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.ordered() {
		if s.ID == id {
			return cloneScan(s), nil
		}
	}
	return core.ScanResult{}, ErrNotFound
}

func (m *Memory) ListScans(_ context.Context, limit int) ([]core.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.ordered()
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	for i := range out {
		out[i].Findings = nil
	}
	return out, nil
}

func (m *Memory) LatestScan(_ context.Context, target string) (core.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.ordered() {
		if s.Target.Name == target {
			return cloneScan(s), nil
		}
	}
	return core.ScanResult{}, ErrNotFound
}

func (m *Memory) ListFindings(_ context.Context, f FindingFilter) ([]core.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []core.Finding
	for _, s := range m.ordered() {
		if f.ScanID != "" && s.ID != f.ScanID {
			continue
		}
		for _, fd := range s.Findings {
			if matches(fd, f) {
				out = append(out, fd)
				if f.Limit > 0 && len(out) >= f.Limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func (m *Memory) Prune(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := make([]core.ScanResult, 0, m.count)
	all := m.ordered()
	for i := len(all) - 1; i >= 0; i-- { // oldest first, so order survives
		if !all[i].FinishedAt.Before(before) {
			kept = append(kept, all[i])
		}
	}
	removed := m.count - len(kept)
	m.buf = make([]core.ScanResult, len(m.buf))
	copy(m.buf, kept)
	m.count = len(kept)
	m.next = len(kept) % len(m.buf)
	return removed, nil
}

func (m *Memory) Close() error { return nil }

// cloneScan copies the slices a caller could mutate, so the store and its
// callers never share backing arrays.
func cloneScan(s core.ScanResult) core.ScanResult {
	s.Findings = slices.Clone(s.Findings)
	s.Skipped = slices.Clone(s.Skipped)
	s.Errors = slices.Clone(s.Errors)
	return s
}

func matches(fd core.Finding, f FindingFilter) bool {
	if f.Severity != nil && fd.Severity != *f.Severity {
		return false
	}
	if f.Category != nil && fd.Category != *f.Category {
		return false
	}
	if f.Status != "" && fd.Status != f.Status {
		return false
	}
	if f.Fingerprint != "" && fd.Fingerprint != f.Fingerprint {
		return false
	}
	return true
}
