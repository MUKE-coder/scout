package core

import (
	"encoding/json"
	"testing"
)

func TestEnumRoundTrip(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		got, err := ParseSeverity(s.String())
		if err != nil || got != s {
			t.Fatalf("severity %v round trip: got %v, %v", s, got, err)
		}
	}
	for _, c := range Categories() {
		got, err := ParseCategory(c.String())
		if err != nil || got != c {
			t.Fatalf("category %v round trip: got %v, %v", c, got, err)
		}
	}
	if _, err := ParseMode("nuclear"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestEnumJSON(t *testing.T) {
	f := Finding{CheckID: "x", Severity: SeverityHigh, Category: CategoryTLS, Confidence: ConfidenceLikely}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Severity != SeverityHigh || back.Category != CategoryTLS || back.Confidence != ConfidenceLikely {
		t.Fatalf("JSON round trip lost enums: %s", b)
	}
}

func TestModeOrdering(t *testing.T) {
	if !(ModePassive < ModeSafe && ModeSafe < ModeActive && ModeActive < ModeIntrusive) {
		t.Fatal("modes must be ordered by aggressiveness")
	}
}

func TestEnvironmentMaxMode(t *testing.T) {
	cases := map[Environment]Mode{EnvDev: ModeIntrusive, EnvStaging: ModeActive, EnvProd: ModeSafe, "weird": ModeSafe}
	for env, want := range cases {
		if got := env.MaxMode(); got != want {
			t.Errorf("%s: MaxMode = %v, want %v", env, got, want)
		}
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Asset{Kind: AssetURL, Value: "https://example.com/", Host: "example.com"}
	f1 := Finding{CheckID: "headers.csp", Asset: a, Severity: SeverityLow, Evidence: Evidence{Response: "one"}}
	f2 := Finding{CheckID: "headers.csp", Asset: a, Severity: SeverityHigh, Evidence: Evidence{Response: "two"}}
	f1.Normalize()
	f2.Normalize()
	if f1.Fingerprint != f2.Fingerprint {
		t.Fatal("fingerprint must ignore evidence and severity")
	}
	if f1.Status != StatusOpen {
		t.Fatalf("default status = %q", f1.Status)
	}
	if Fingerprint("headers.csp", a, "cookie:sid") == f1.Fingerprint {
		t.Fatal("location must change the fingerprint")
	}
	if Fingerprint("headers.hsts", a, "") == f1.Fingerprint {
		t.Fatal("check ID must change the fingerprint")
	}
}

func TestTarget(t *testing.T) {
	cases := []struct {
		url   string
		local bool
	}{
		{"http://localhost:8080", true},
		{"http://127.0.0.1", true},
		{"http://192.168.1.10", true},
		{"https://example.com", false},
		{"https://8.8.8.8", false},
	}
	for _, c := range cases {
		tg := Target{Name: "t", URL: c.url, Environment: EnvDev}
		if err := tg.Validate(); err != nil {
			t.Errorf("%s: %v", c.url, err)
		}
		if tg.IsLocal() != c.local {
			t.Errorf("%s: IsLocal = %v", c.url, !c.local)
		}
	}
	if err := (Target{Name: "bad", URL: "ftp://x", Environment: EnvDev}).Validate(); err == nil {
		t.Error("ftp URL should be rejected")
	}
	if err := (Target{Name: "empty", Environment: EnvDev}).Validate(); err == nil {
		t.Error("empty target should be rejected")
	}
}
