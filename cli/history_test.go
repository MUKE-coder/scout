package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/storage"
)

// seedHistory stores three scans of one target: x and y, then y only, then
// x (back) and z (new).
func seedHistory(t *testing.T) (string, []string) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "scout.db")
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	target := core.Target{Name: "site", URL: "https://example.com", Environment: core.EnvDev}
	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string, at time.Time) core.Finding {
		return core.Finding{Fingerprint: id, Title: id, Severity: core.SeverityHigh, Status: core.StatusOpen, FirstSeen: at, LastSeen: at}
	}
	scans := []struct {
		id       string
		findings []string
	}{
		{"aaaa1111", []string{"x", "y"}},
		{"bbbb2222", []string{"y"}},
		{"cccc3333", []string{"x", "y", "z"}},
	}
	var ids []string
	for i, s := range scans {
		at := day.Add(time.Duration(i) * 24 * time.Hour)
		sc := core.ScanResult{ID: s.id, Target: target, StartedAt: at, FinishedAt: at.Add(time.Minute)}
		for _, f := range s.findings {
			sc.Findings = append(sc.Findings, mk(f, at.Add(time.Minute)))
		}
		if err := store.SaveScan(context.Background(), sc); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.id)
	}
	return db, ids
}

func TestDiffCommand(t *testing.T) {
	db, _ := seedHistory(t)
	// Prefixes, and arguments in the "wrong" order are swapped to old -> new.
	out, err := run("diff", "cccc", "bbbb", "--db", db, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Diff
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if d.From != "bbbb2222" || d.To != "cccc3333" {
		t.Fatalf("direction = %s -> %s", d.From, d.To)
	}
	if ids(d.New) != "z" || ids(d.Regressed) != "x" || ids(d.Unchanged) != "y" || len(d.Fixed) != 0 {
		t.Fatalf("new=%s regressed=%s unchanged=%s fixed=%s", ids(d.New), ids(d.Regressed), ids(d.Unchanged), ids(d.Fixed))
	}

	out, err = run("diff", "aaaa", "bbbb", "--db", db, "--color", "never")
	if err != nil || !strings.Contains(out, "0 new · 0 regressed · 1 fixed · 1 unchanged") {
		t.Fatalf("pretty diff: %v\n%s", err, out)
	}
}

func TestPruneCommand(t *testing.T) {
	db, _ := seedHistory(t) // three scans dated Oct 1-3 2026
	out, err := run("prune", "--db", db, "--retention", "1h")
	if err != nil || !strings.Contains(out, "Removed 3 scan(s)") {
		t.Fatalf("prune: %v %q", err, out)
	}
}

func TestDiffUnknownScan(t *testing.T) {
	db, _ := seedHistory(t)
	if _, err := run("diff", "zzzz", "aaaa", "--db", db); err == nil || !strings.Contains(err.Error(), "no scan matches") {
		t.Fatalf("err = %v", err)
	}
}

func ids(fs []core.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Fingerprint)
	}
	return strings.Join(out, ",")
}
