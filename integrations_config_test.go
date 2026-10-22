package scout

import (
	"log/slog"
	"strings"
	"testing"
)

func TestIntegrationsConfig(t *testing.T) {
	yaml := `
integrations:
  pulse:
    url: http://localhost:7070
  sentinel:
    url: https://sentinel.example.com
    path: /custom/score
`
	c, err := LoadConfig(writeFile(t, yaml), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := c.Integrations.dispatcher(nil, env(map[string]string{"SCOUT_PULSE_TOKEN": "p"}), slog.New(slog.DiscardHandler))
	if d == nil || d.Pulse == nil || d.Sentinel == nil {
		t.Fatalf("dispatcher = %+v", d)
	}

	// No integrations configured -> no dispatcher.
	bare, _ := LoadConfig(writeFile(t, "integrations: {}\n"), nil)
	if bare.Integrations.dispatcher(nil, env(nil), slog.New(slog.DiscardHandler)) != nil {
		t.Fatal("empty integrations should yield no dispatcher")
	}

	if _, err := LoadConfig(writeFile(t, "integrations:\n  pulse: {url: 'not a url'}\n"), nil); err == nil ||
		!strings.Contains(err.Error(), "pulse.url") {
		t.Fatalf("bad pulse url should be rejected: %v", err)
	}
}
