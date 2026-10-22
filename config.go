package scout

import (
	"fmt"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// Scope limits what a scan may touch. Empty Hosts means "only the target's
// own host"; Scout never widens scope implicitly.
type Scope struct {
	Hosts        []string `json:"hosts,omitempty" yaml:"hosts"`
	IncludePaths []string `json:"include_paths,omitempty" yaml:"include_paths"`
	ExcludePaths []string `json:"exclude_paths,omitempty" yaml:"exclude_paths"`
}

// Config is the full Scout configuration. Build it directly or with options.
type Config struct {
	AppName     string           `json:"app_name" yaml:"app_name"`
	Environment core.Environment `json:"environment" yaml:"environment"`
	// Mode is the requested mode. It is always capped by the environment.
	Mode    core.Mode     `json:"mode" yaml:"mode"`
	Targets []core.Target `json:"targets,omitempty" yaml:"targets"`
	Scope   Scope         `json:"scope" yaml:"scope"`

	// RateLimit is the max outbound requests per second per target.
	RateLimit int `json:"rate_limit" yaml:"rate_limit"`
	// Concurrency is the number of checks run in parallel.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// CheckTimeout bounds a single check run.
	CheckTimeout time.Duration `json:"check_timeout" yaml:"check_timeout"`

	// DBPath is the SQLite file. Empty uses in-memory storage only.
	DBPath string `json:"db_path" yaml:"db_path"`
	// Retention is how long scan history is kept.
	Retention time.Duration `json:"retention" yaml:"retention"`

	// SigningKey signs the X-Scout-Scan self-test header. Generated if empty.
	SigningKey string `json:"-" yaml:"signing_key"`

	// Dashboard credentials. Defaults are refused outside dev.
	Username  string `json:"-" yaml:"username"`
	Password  string `json:"-" yaml:"password"`
	JWTSecret string `json:"-" yaml:"jwt_secret"`
}

// Defaults for a fresh Config.
const (
	DefaultRateLimit    = 10
	DefaultConcurrency  = 4
	DefaultCheckTimeout = 60 * time.Second
	DefaultRetention    = 90 * 24 * time.Hour
	DefaultUsername     = "admin"
	DefaultPassword     = "scout"
)

// DefaultConfig returns a dev-safe config: dev environment, Safe mode.
func DefaultConfig() Config {
	return Config{
		AppName:      "Scout",
		Environment:  core.EnvDev,
		Mode:         core.ModeSafe,
		RateLimit:    DefaultRateLimit,
		Concurrency:  DefaultConcurrency,
		CheckTimeout: DefaultCheckTimeout,
		Retention:    DefaultRetention,
		Username:     DefaultUsername,
		Password:     DefaultPassword,
	}
}

// Option mutates a Config.
type Option func(*Config)

// WithConfig replaces the whole config; later options still apply on top.
func WithConfig(c Config) Option { return func(dst *Config) { *dst = c } }

// WithTarget adds a target URL in the current environment.
func WithTarget(url string) Option {
	return func(c *Config) {
		c.Targets = append(c.Targets, core.Target{Name: url, URL: url, Environment: c.Environment})
	}
}

// WithMode sets the requested scan mode.
func WithMode(m core.Mode) Option { return func(c *Config) { c.Mode = m } }

// WithEnvironment sets the environment, which caps the mode.
func WithEnvironment(e core.Environment) Option { return func(c *Config) { c.Environment = e } }

// WithScope sets the scope allowlist.
func WithScope(s Scope) Option { return func(c *Config) { c.Scope = s } }

// WithDB sets the SQLite file path.
func WithDB(path string) Option { return func(c *Config) { c.DBPath = path } }

// NewConfig builds a config from defaults plus options, then validates it.
func NewConfig(opts ...Option) (Config, error) {
	c := DefaultConfig()
	for _, o := range opts {
		o(&c)
	}
	c.applyDefaults()
	return c, c.Validate()
}

func (c *Config) applyDefaults() {
	if c.Environment == "" {
		c.Environment = core.EnvDev
	}
	if c.RateLimit <= 0 {
		c.RateLimit = DefaultRateLimit
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.CheckTimeout <= 0 {
		c.CheckTimeout = DefaultCheckTimeout
	}
	if c.Retention <= 0 {
		c.Retention = DefaultRetention
	}
	for i := range c.Targets {
		if c.Targets[i].Environment == "" {
			c.Targets[i].Environment = c.Environment
		}
	}
}

// Validate rejects unsafe or inconsistent configuration.
func (c Config) Validate() error {
	if _, err := core.ParseEnvironment(string(c.Environment)); err != nil {
		return err
	}
	if c.Mode < core.ModePassive || c.Mode > core.ModeIntrusive {
		return fmt.Errorf("invalid mode %d", c.Mode)
	}
	for _, t := range c.Targets {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateDashboard adds the checks needed before serving the dashboard:
// default credentials are refused outside dev.
func (c Config) ValidateDashboard() error {
	if c.Environment != core.EnvDev && c.UsesDefaultCredentials() {
		return fmt.Errorf("default dashboard credentials are refused in %s: set Username/Password", c.Environment)
	}
	return nil
}

// UsesDefaultCredentials reports whether the dashboard login is unchanged.
func (c Config) UsesDefaultCredentials() bool {
	return c.Username == DefaultUsername && c.Password == DefaultPassword
}

// EffectiveMode is the requested mode capped by the environment.
func (c Config) EffectiveMode() core.Mode {
	if max := c.Environment.MaxMode(); c.Mode > max {
		return max
	}
	return c.Mode
}
