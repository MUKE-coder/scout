package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// fixtureFindings is what the fixture check reports on its next run.
var fixtureFindings []core.Finding

func useFixtureCheck(t *testing.T) {
	t.Helper()
	reg := core.NewRegistry()
	reg.MustRegister(core.CheckFunc{
		CheckID: "fixture.check", CheckCategory: core.CategoryApp, CheckMode: core.ModePassive,
		Fn: func(context.Context, core.Target) ([]core.Finding, error) {
			return append([]core.Finding(nil), fixtureFindings...), nil
		},
	})
	old := registry
	registry = reg
	t.Cleanup(func() { registry, fixtureFindings = old, nil })
}

func fixture(path string, sev core.Severity) core.Finding {
	return core.Finding{Title: path, Category: core.CategoryApp, Severity: sev, Confidence: core.ConfidenceConfirmed,
		Asset: core.Asset{Kind: core.AssetURL, Value: "http://localhost:1" + path, Path: path}}
}

func ciRun(db string, extra ...string) (string, error) {
	args := append([]string{"ci", "--target", "http://localhost:1", "--db", db, "--color", "never"}, extra...)
	return run(args...)
}

func TestCIGate(t *testing.T) {
	useFixtureCheck(t)
	db := filepath.Join(t.TempDir(), "scout.db")
	fixtureFindings = []core.Finding{fixture("/a", core.SeverityHigh), fixture("/b", core.SeverityLow)}

	out, err := ciRun(db, "--fail-on", "high")
	var gate *GateError
	if !errors.As(err, &gate) || gate.Count != 1 || ExitCode(err) != ExitGateFailed {
		t.Fatalf("high finding should fail the gate: err=%v\n%s", err, out)
	}
	if !strings.Contains(out, "FAIL: 1 open finding(s) at or above high") {
		t.Fatalf("missing verdict:\n%s", out)
	}

	out, err = ciRun(db, "--fail-on", "critical")
	if err != nil || ExitCode(err) != ExitOK || !strings.Contains(out, "PASS") {
		t.Fatalf("no critical findings should pass: err=%v\n%s", err, out)
	}
}

func TestCINewOnly(t *testing.T) {
	useFixtureCheck(t)
	db := filepath.Join(t.TempDir(), "scout.db")
	fixtureFindings = []core.Finding{fixture("/a", core.SeverityHigh)}

	// First run: no history, so the existing high counts as new.
	out, err := ciRun(db, "--new-only")
	if ExitCode(err) != ExitGateFailed || !strings.Contains(out, "every finding counts as new") {
		t.Fatalf("first run should fail safe: err=%v\n%s", err, out)
	}

	// Same findings again: nothing new.
	out, err = ciRun(db, "--new-only")
	if err != nil {
		t.Fatalf("unchanged findings should pass with --new-only: %v\n%s", err, out)
	}

	// A new high appears.
	fixtureFindings = append(fixtureFindings, fixture("/new", core.SeverityHigh))
	out, err = ciRun(db, "--new-only")
	var gate *GateError
	if !errors.As(err, &gate) || gate.Count != 1 || !strings.Contains(out, "new or regressed") {
		t.Fatalf("one new high should fail: err=%v\n%s", err, out)
	}
}

func TestExitCodes(t *testing.T) {
	if ExitCode(nil) != ExitOK || ExitCode(errors.New("boom")) != ExitError ||
		ExitCode(&GateError{Count: 1}) != ExitGateFailed {
		t.Fatal("exit code mapping wrong")
	}
	if _, err := run("ci", "--target", "http://localhost:1", "--db", "", "--fail-on", "spicy"); ExitCode(err) != ExitError {
		t.Fatalf("bad flag should exit %d", ExitError)
	}
}
