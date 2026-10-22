package scout

import (
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestAlertsConfig(t *testing.T) {
	yaml := `
alerts:
  min_severity: medium
  dashboard_url: https://scout.example.com/scout/ui/
  slack: { webhook_url: "https://hooks.slack.com/services/T/B/X" }
  webhooks:
    - url: https://ops.example.com/scout
      secret: shared-secret
  email:
    host: smtp.example.com
    from: scout@example.com
    to: [ops@example.com]
`
	c, err := LoadConfig(writeFile(t, yaml), env(map[string]string{"SCOUT_SMTP_PASSWORD": "from-env", "SCOUT_DISCORD_WEBHOOK": "https://discord.com/api/webhooks/1/x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Alerts.Email.Password != "from-env" || c.Alerts.Discord == nil {
		t.Fatalf("env not applied: %+v", c.Alerts)
	}
	d := c.Alerts.dispatcher(nil, nil)
	if d == nil || len(d.Notifiers) != 4 || d.MinSeverity != core.SeverityMedium {
		t.Fatalf("dispatcher = %+v", d)
	}
}

func TestAlertsConfigRejects(t *testing.T) {
	cases := map[string]string{
		"unsigned webhook": "alerts:\n  webhooks: [{url: 'https://x.example'}]\n",
		"bad slack url":    "alerts:\n  slack: {webhook_url: 'not a url'}\n",
		"email no to":      "alerts:\n  email: {host: smtp.x, from: a@x}\n",
		"bad severity":     "alerts:\n  min_severity: spicy\n",
	}
	for name, y := range cases {
		if _, err := LoadConfig(writeFile(t, y), nil); err == nil || !strings.Contains(err.Error(), "alerts") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// No channels means no dispatcher.
	c, _ := LoadConfig(writeFile(t, "alerts:\n  min_severity: high\n"), nil)
	if c.Alerts.dispatcher(nil, nil) != nil {
		t.Fatal("dispatcher without channels")
	}
}
