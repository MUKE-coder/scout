package scout

import (
	"fmt"
	"log/slog"
	"net/url"

	"github.com/MUKE-coder/scout/integrations"
	"github.com/MUKE-coder/scout/storage"
)

// SiblingConfig points Scout at a Pulse or Sentinel instance. Tokens come
// from the environment (SCOUT_PULSE_TOKEN, SCOUT_SENTINEL_TOKEN), not the
// file.
type SiblingConfig struct {
	URL  string `json:"url,omitempty" yaml:"url"`
	Path string `json:"path,omitempty" yaml:"path"`
}

// IntegrationsConfig configures the optional Pulse and Sentinel links.
type IntegrationsConfig struct {
	Pulse    *SiblingConfig `json:"pulse,omitempty" yaml:"pulse"`
	Sentinel *SiblingConfig `json:"sentinel,omitempty" yaml:"sentinel"`
}

func validSiblingURL(name string, s *SiblingConfig) error {
	if s == nil || s.URL == "" {
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("integrations: %s.url must be an http(s) URL", name)
	}
	return nil
}

// Validate checks the integration URLs.
func (c *IntegrationsConfig) Validate() error {
	if c == nil {
		return nil
	}
	if err := validSiblingURL("pulse", c.Pulse); err != nil {
		return err
	}
	return validSiblingURL("sentinel", c.Sentinel)
}

// dispatcher builds the integrations dispatcher, or nil when nothing is
// configured. Tokens are read from the environment.
func (c *IntegrationsConfig) dispatcher(store storage.Store, getenv func(string) string, log *slog.Logger) *integrations.Dispatcher {
	if c == nil {
		return nil
	}
	d := &integrations.Dispatcher{Store: store, Logger: log}
	if c.Pulse != nil && c.Pulse.URL != "" {
		d.Pulse = integrations.NewPulse(c.Pulse.URL, c.Pulse.Path, getenv("SCOUT_PULSE_TOKEN"))
	}
	if c.Sentinel != nil && c.Sentinel.URL != "" {
		d.Sentinel = integrations.NewSentinel(c.Sentinel.URL, c.Sentinel.Path, getenv("SCOUT_SENTINEL_TOKEN"))
	}
	if !d.Active() {
		return nil
	}
	return d
}
