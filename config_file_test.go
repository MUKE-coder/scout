package scout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scout.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const sampleYAML = `
app_name: Shop
environment: staging
mode: active
targets:
  - name: shop
    url: https://shop.example.com
    allow_active: true
    criticality: 1.5
scope:
  hosts: [shop.example.com, "*.cdn.example.com"]
  exclude_paths: [/logout]
criticality:
  - host: shop.example.com
    path_prefix: /checkout
    value: 1.5
rate_limit: 5
concurrency: 2
check_timeout: 30s
db: /var/lib/scout/scout.db
retention: 720h
window:
  start: "02:00"
  end: "05:00"
  days: [mon, Tuesday]
  timezone: UTC
username: ops
password: s3cret-long-password
`

func TestLoadConfigFile(t *testing.T) {
	c, err := LoadConfig(writeFile(t, sampleYAML), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.AppName != "Shop" || c.Environment != core.EnvStaging || c.Mode != core.ModeActive {
		t.Fatalf("basics: %+v", c)
	}
	if len(c.Targets) != 1 || !c.Targets[0].AllowActive || c.Targets[0].Environment != core.EnvStaging || c.Targets[0].Criticality != 1.5 {
		t.Fatalf("targets: %+v", c.Targets)
	}
	if len(c.Scope.Hosts) != 2 || c.Scope.ExcludePaths[0] != "/logout" || len(c.Criticality) != 1 {
		t.Fatalf("scope/criticality: %+v %+v", c.Scope, c.Criticality)
	}
	if c.RateLimit != 5 || c.Concurrency != 2 || c.CheckTimeout != 30*time.Second || c.Retention != 720*time.Hour || c.DBPath != "/var/lib/scout/scout.db" {
		t.Fatalf("numbers: %+v", c)
	}
	w, err := c.Window.EngineWindow()
	if err != nil || len(w.Days) != 2 || w.Days[1] != time.Tuesday || w.Location.String() != "UTC" {
		t.Fatalf("window: %+v %v", w, err)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	c, err := LoadConfig(writeFile(t, sampleYAML), env(map[string]string{
		"SCOUT_ENV":           "prod",
		"SCOUT_MODE":          "safe",
		"SCOUT_TARGETS":       "https://a.example.com, https://b.example.com",
		"SCOUT_RATE_LIMIT":    "20",
		"SCOUT_CHECK_TIMEOUT": "2m",
		"SCOUT_DB":            "other.db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Environment != core.EnvProd || c.Mode != core.ModeSafe || c.RateLimit != 20 || c.CheckTimeout != 2*time.Minute || c.DBPath != "other.db" {
		t.Fatalf("env not applied: %+v", c)
	}
	if len(c.Targets) != 2 || c.Targets[1].URL != "https://b.example.com" || c.Targets[0].Environment != core.EnvProd {
		t.Fatalf("SCOUT_TARGETS: %+v", c.Targets)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	cases := map[string]struct {
		yaml string
		env  map[string]string
		want string
	}{
		"typo key":     {yaml: "rate_limt: 5\n", want: "rate_limt"},
		"bad mode":     {yaml: "mode: nuclear\n", want: "unknown mode"},
		"bad window":   {yaml: "window: {start: 2am, end: \"05:00\"}\n", want: "HH:MM"},
		"bad day":      {yaml: "window: {start: \"01:00\", end: \"05:00\", days: [funday]}\n", want: "unknown day"},
		"bad env var":  {env: map[string]string{"SCOUT_RATE_LIMIT": "fast"}, want: "SCOUT_RATE_LIMIT"},
		"bad env mode": {env: map[string]string{"SCOUT_MODE": "loud"}, want: "SCOUT_MODE"},
		"bad target":   {yaml: "targets: [{name: x, url: 'ftp://x'}]\n", want: "not an http(s) URL"},
	}
	for name, c := range cases {
		path := ""
		if c.yaml != "" {
			path = writeFile(t, c.yaml)
		}
		_, err := LoadConfig(path, env(c.env))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	if _, err := LoadConfig("scout.example.yaml", nil); err != nil {
		t.Fatalf("scout.example.yaml must stay valid: %v", err)
	}
}

func TestLoadConfigEmptyFileAndNoFile(t *testing.T) {
	for _, path := range []string{writeFile(t, ""), ""} {
		c, err := LoadConfig(path, nil)
		if err != nil || c.Mode != core.ModeSafe || c.Environment != core.EnvDev {
			t.Fatalf("path %q: %+v %v", path, c, err)
		}
	}
}
