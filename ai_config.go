package scout

import (
	"fmt"
	"log/slog"
	"net/url"

	"github.com/MUKE-coder/scout/ai"
)

// AIConfig enables optional AI explanations through the Vercel AI Gateway.
// The API key is read only from the AI_GATEWAY_API_KEY environment variable
// so it never lands in scout.yaml.
type AIConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Model is any AI Gateway model ID, e.g. "anthropic/claude-sonnet-5.5".
	Model string `json:"model,omitempty" yaml:"model"`
	// BaseURL overrides the Gateway endpoint (OpenAI-compatible).
	BaseURL string `json:"base_url,omitempty" yaml:"base_url"`
}

// Validate checks the AI settings.
func (a *AIConfig) Validate() error {
	if a == nil || a.BaseURL == "" {
		return nil
	}
	u, err := url.Parse(a.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("ai: base_url must be an https URL")
	}
	return nil
}

// client returns the AI client, or nil when AI is off or has no key.
func (a *AIConfig) client(getenv func(string) string, log *slog.Logger) *ai.Client {
	if a == nil || !a.Enabled {
		return nil
	}
	key := getenv(ai.APIKeyEnv)
	if key == "" {
		log.Warn("ai.enabled is set but " + ai.APIKeyEnv + " is empty: AI features stay off")
		return nil
	}
	c := &ai.Client{BaseURL: a.BaseURL, APIKey: key, Model: a.Model}
	log.Info("ai explanations enabled via Vercel AI Gateway", "model", c.Model)
	return c
}
