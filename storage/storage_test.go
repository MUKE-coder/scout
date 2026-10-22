package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

func sampleScan(id, target string, finished time.Time) core.ScanResult {
	f := core.Finding{
		CheckID: "headers.csp", Title: "Missing CSP", Category: core.CategoryHeaders,
		Severity: core.SeverityMedium, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetURL, Value: target},
	}
	f.Normalize()
	g := core.Finding{
		CheckID: "tls.expired", Title: "Expired cert", Category: core.CategoryTLS,
		Severity: core.SeverityHigh, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetDomain, Value: target},
	}
	g.Normalize()
	return core.ScanResult{
		ID: id, Target: core.Target{Name: target, URL: target, Environment: core.EnvDev},
		Mode: core.ModeSafe, StartedAt: finished.Add(-time.Minute), FinishedAt: finished,
		Findings: []core.Finding{f, g}, Score: 72.5, Grade: "C",
		Skipped: []core.SkippedCheck{{CheckID: "app.sqli", Mode: core.ModeActive, Reason: "mode cap"}},
	}
}

// storeContract runs the same behavioral tests against every backend.
func storeContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := s.GetScan(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetScan(missing) err = %v", err)
	}

	old := sampleScan("s1", "https://a.example", now.Add(-48*time.Hour))
	newer := sampleScan("s2", "https://a.example", now)
	other := sampleScan("s3", "https://b.example", now.Add(-time.Hour))
	for _, sc := range []core.ScanResult{old, other, newer} {
		if err := s.SaveScan(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GetScan(ctx, "s2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Grade != "C" || len(got.Findings) != 2 || len(got.Skipped) != 1 || got.Target.URL != "https://a.example" {
		t.Fatalf("GetScan round trip lost data: %+v", got)
	}

	latest, err := s.LatestScan(ctx, "https://a.example")
	if err != nil || latest.ID != "s2" {
		t.Fatalf("LatestScan = %s, %v", latest.ID, err)
	}

	list, err := s.ListScans(ctx, 10)
	if err != nil || len(list) != 3 || list[0].ID != "s2" {
		t.Fatalf("ListScans = %v, %v", ids(list), err)
	}

	high := core.SeverityHigh
	fs, err := s.ListFindings(ctx, FindingFilter{ScanID: "s2", Severity: &high})
	if err != nil || len(fs) != 1 || fs[0].CheckID != "tls.expired" {
		t.Fatalf("ListFindings(high) = %+v, %v", fs, err)
	}

	// Re-saving replaces rather than duplicating findings.
	if err := s.SaveScan(ctx, newer); err != nil {
		t.Fatal(err)
	}
	fs, _ = s.ListFindings(ctx, FindingFilter{ScanID: "s2"})
	if len(fs) != 2 {
		t.Fatalf("re-save duplicated findings: %d", len(fs))
	}

	n, err := s.Prune(ctx, now.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	if _, err := s.GetScan(ctx, "s1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("pruned scan still present")
	}
	if fs, _ := s.ListFindings(ctx, FindingFilter{ScanID: "s1"}); len(fs) != 0 {
		t.Fatal("pruned scan's findings still present")
	}
}

func ids(l []core.ScanResult) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = s.ID
	}
	return out
}

func TestMemoryStore(t *testing.T) { storeContract(t, NewMemory(10)) }

func TestSQLiteStore(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "scout.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	storeContract(t, s)
}

func TestMemoryDoesNotAlias(t *testing.T) {
	m := NewMemory(3)
	ctx := context.Background()
	sc := sampleScan("s1", "https://a.example", time.Now())
	_ = m.SaveScan(ctx, sc)
	sc.Findings[0].Title = "mutated after save"
	got, _ := m.GetScan(ctx, "s1")
	got.Findings[1].Title = "mutated after read"
	again, _ := m.GetScan(ctx, "s1")
	if again.Findings[0].Title != "Missing CSP" || again.Findings[1].Title != "Expired cert" {
		t.Fatalf("store shares memory with callers: %q, %q", again.Findings[0].Title, again.Findings[1].Title)
	}
}

func TestMemoryRingOverwritesOldest(t *testing.T) {
	m := NewMemory(3)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		_ = m.SaveScan(ctx, core.ScanResult{ID: fmt.Sprintf("s%d", i)})
	}
	list, _ := m.ListScans(ctx, 0)
	if got := ids(list); fmt.Sprint(got) != "[s5 s4 s3]" {
		t.Fatalf("ring contents = %v", got)
	}
}
