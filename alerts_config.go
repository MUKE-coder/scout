package scout

import (
	"fmt"
	"log/slog"
	"net/url"

	"github.com/MUKE-coder/scout/alerts"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/storage"
)

// AlertsConfig configures notifications for new or regressed findings.
type AlertsConfig struct {
	// MinSeverity is the lowest severity that alerts (default high).
	MinSeverity string `json:"min_severity,omitempty" yaml:"min_severity"`
	// DashboardURL is linked from every alert.
	DashboardURL string           `json:"dashboard_url,omitempty" yaml:"dashboard_url"`
	Slack        *alerts.Slack    `json:"-" yaml:"slack"`
	Discord      *alerts.Discord  `json:"-" yaml:"discord"`
	Email        *alerts.Email    `json:"-" yaml:"email"`
	Webhooks     []alerts.Webhook `json:"-" yaml:"webhooks"`
}

func (a *AlertsConfig) minSeverity() (core.Severity, error) {
	if a.MinSeverity == "" {
		return core.SeverityHigh, nil
	}
	return core.ParseSeverity(a.MinSeverity)
}

func httpURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("alerts: %s must be an http(s) URL", field)
	}
	return nil
}

// Validate checks every configured channel.
func (a *AlertsConfig) Validate() error {
	if a == nil {
		return nil
	}
	if _, err := a.minSeverity(); err != nil {
		return fmt.Errorf("alerts: %w", err)
	}
	if a.Slack != nil {
		if err := httpURL("slack.webhook_url", a.Slack.WebhookURL); err != nil {
			return err
		}
	}
	if a.Discord != nil {
		if err := httpURL("discord.webhook_url", a.Discord.WebhookURL); err != nil {
			return err
		}
	}
	for i, w := range a.Webhooks {
		if err := httpURL(fmt.Sprintf("webhooks[%d].url", i), w.URL); err != nil {
			return err
		}
		if w.Secret == "" {
			return fmt.Errorf("alerts: webhooks[%d] needs a secret so receivers can verify Scout's signature", i)
		}
	}
	if e := a.Email; e != nil {
		if e.Host == "" || e.From == "" || len(e.To) == 0 {
			return fmt.Errorf("alerts: email needs host, from and at least one recipient in to")
		}
	}
	return nil
}

// notifiers returns the configured channels.
func (a *AlertsConfig) notifiers() []alerts.Notifier {
	var out []alerts.Notifier
	if a.Slack != nil {
		out = append(out, *a.Slack)
	}
	if a.Discord != nil {
		out = append(out, *a.Discord)
	}
	if a.Email != nil {
		out = append(out, *a.Email)
	}
	for _, w := range a.Webhooks {
		out = append(out, w)
	}
	return out
}

// dispatcher builds the alert dispatcher, or nil when nothing is configured.
func (a *AlertsConfig) dispatcher(store storage.Store, log *slog.Logger) *alerts.Dispatcher {
	if a == nil {
		return nil
	}
	ns := a.notifiers()
	if len(ns) == 0 {
		return nil
	}
	min, _ := a.minSeverity() // validated at load
	return &alerts.Dispatcher{Notifiers: ns, MinSeverity: min, DashboardURL: a.DashboardURL, Store: store, Logger: log}
}

// applyAlertEnv lets secrets come from the environment instead of the file.
func applyAlertEnv(c *Config, getenv func(string) string) {
	slack, discord, smtpPass := getenv("SCOUT_SLACK_WEBHOOK"), getenv("SCOUT_DISCORD_WEBHOOK"), getenv("SCOUT_SMTP_PASSWORD")
	if slack == "" && discord == "" && smtpPass == "" {
		return
	}
	if c.Alerts == nil {
		c.Alerts = &AlertsConfig{}
	}
	if slack != "" {
		c.Alerts.Slack = &alerts.Slack{WebhookURL: slack}
	}
	if discord != "" {
		c.Alerts.Discord = &alerts.Discord{WebhookURL: discord}
	}
	if smtpPass != "" && c.Alerts.Email != nil {
		c.Alerts.Email.Password = smtpPass
	}
}
