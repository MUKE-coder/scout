package scout

import (
	"log/slog"
	"testing"
)

func TestAIConfig(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	c, err := LoadConfig(writeFile(t, "ai:\n  enabled: true\n  model: openai/gpt-x\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.AI.client(env(nil), log) != nil {
		t.Fatal("no key in the environment must keep AI off")
	}
	cl := c.AI.client(env(map[string]string{"AI_GATEWAY_API_KEY": "vck_x"}), log)
	if cl == nil || cl.Model != "openai/gpt-x" || cl.APIKey != "vck_x" {
		t.Fatalf("client = %+v", cl)
	}
	off, _ := LoadConfig(writeFile(t, "ai:\n  enabled: false\n"), nil)
	if off.AI.client(env(map[string]string{"AI_GATEWAY_API_KEY": "vck_x"}), log) != nil {
		t.Fatal("enabled: false must keep AI off even with a key")
	}
	if _, err := LoadConfig(writeFile(t, "ai:\n  base_url: http://insecure.example\n"), nil); err == nil {
		t.Fatal("non-https base_url must be rejected")
	}
	if _, err := LoadConfig(writeFile(t, "ai:\n  api_key: oops\n"), nil); err == nil {
		t.Fatal("api_key in the file must be rejected (keys come from the environment)")
	}
}
