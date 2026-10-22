package scout

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
)

// DefaultConfigFile is looked for in the working directory when no
// --config path is given.
const DefaultConfigFile = "scout.yaml"

// ScanWindow is the config-file form of a daily scan window.
type ScanWindow struct {
	Start    string   `json:"start" yaml:"start"` // "HH:MM"
	End      string   `json:"end" yaml:"end"`     // "HH:MM"; before Start wraps past midnight
	Days     []string `json:"days,omitempty" yaml:"days"`
	Timezone string   `json:"timezone,omitempty" yaml:"timezone"` // IANA name; empty is local time
}

var weekdays = map[string]time.Weekday{}

func init() {
	for d := time.Sunday; d <= time.Saturday; d++ {
		name := strings.ToLower(d.String())
		weekdays[name] = d     // "monday"
		weekdays[name[:3]] = d // "mon"
	}
}

// EngineWindow converts the window for the engine. A nil window is nil.
func (w *ScanWindow) EngineWindow() (*engine.Window, error) {
	if w == nil {
		return nil, nil
	}
	for _, t := range []string{w.Start, w.End} {
		if _, err := time.Parse("15:04", strings.TrimSpace(t)); err != nil {
			return nil, fmt.Errorf("window: %q is not a HH:MM time", t)
		}
	}
	out := &engine.Window{Start: w.Start, End: w.End}
	for _, d := range w.Days {
		wd, ok := weekdays[strings.ToLower(strings.TrimSpace(d))]
		if !ok {
			return nil, fmt.Errorf("window: unknown day %q", d)
		}
		out.Days = append(out.Days, wd)
	}
	if w.Timezone != "" {
		loc, err := time.LoadLocation(w.Timezone)
		if err != nil {
			return nil, fmt.Errorf("window: %w", err)
		}
		out.Location = loc
	}
	return out, nil
}

// LoadConfig builds a Config from defaults, then the YAML file at path (if
// path is non-empty), then SCOUT_* environment variables read with getenv.
// Callers apply command-line flags last. The file is decoded strictly: an
// unknown key is an error, so a typo cannot silently disable a setting.
func LoadConfig(path string, getenv func(string) string) (Config, error) {
	c := DefaultConfig()
	if path != "" {
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return c, fmt.Errorf("config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) { // EOF: empty file keeps defaults
			return c, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if err := applyEnv(&c, getenv); err != nil {
		return c, err
	}
	c.applyDefaults()
	if _, err := c.Window.EngineWindow(); err != nil {
		return c, err
	}
	return c, c.Validate()
}

// FindConfig returns explicit if set, else DefaultConfigFile when it exists
// in the working directory, else "".
func FindConfig(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		return DefaultConfigFile
	}
	return ""
}

// applyEnv overrides fields from SCOUT_* environment variables.
func applyEnv(c *Config, getenv func(string) string) error {
	if getenv == nil {
		return nil
	}
	str := func(key string, dst *string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	str("SCOUT_APP_NAME", &c.AppName)
	str("SCOUT_DB", &c.DBPath)
	str("SCOUT_SIGNING_KEY", &c.SigningKey)
	str("SCOUT_USERNAME", &c.Username)
	str("SCOUT_PASSWORD", &c.Password)
	str("SCOUT_JWT_SECRET", &c.JWTSecret)
	applyAlertEnv(c, getenv)

	if v := getenv("SCOUT_ENV"); v != "" {
		env, err := core.ParseEnvironment(v)
		if err != nil {
			return fmt.Errorf("SCOUT_ENV: %w", err)
		}
		c.Environment = env
		for i := range c.Targets {
			c.Targets[i].Environment = env
		}
	}
	if v := getenv("SCOUT_MODE"); v != "" {
		m, err := core.ParseMode(v)
		if err != nil {
			return fmt.Errorf("SCOUT_MODE: %w", err)
		}
		c.Mode = m
	}
	if v := getenv("SCOUT_TARGETS"); v != "" {
		c.Targets = nil
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				c.Targets = append(c.Targets, core.Target{Name: u, URL: u, Environment: c.Environment})
			}
		}
	}
	for key, dst := range map[string]*int{"SCOUT_RATE_LIMIT": &c.RateLimit, "SCOUT_CONCURRENCY": &c.Concurrency} {
		if v := getenv(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return fmt.Errorf("%s: want a positive integer, got %q", key, v)
			}
			*dst = n
		}
	}
	for key, dst := range map[string]*time.Duration{"SCOUT_CHECK_TIMEOUT": &c.CheckTimeout, "SCOUT_RETENTION": &c.Retention} {
		if v := getenv(key); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return fmt.Errorf("%s: want a duration like 60s or 2160h, got %q", key, v)
			}
			*dst = d
		}
	}
	return nil
}
