package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// Defaults for the Vercel AI Gateway (OpenAI-compatible Chat Completions).
const (
	DefaultBaseURL = "https://ai-gateway.vercel.sh/v1"
	DefaultModel   = "anthropic/claude-sonnet-5.5"
	// APIKeyEnv is the Gateway's standard environment variable.
	APIKeyEnv = "AI_GATEWAY_API_KEY"
)

// ErrDisabled is returned when AI is not configured.
var ErrDisabled = errors.New("ai: not configured (set ai.enabled and AI_GATEWAY_API_KEY)")

// Client calls a model through the Vercel AI Gateway.
type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

// Enabled reports whether the client can make calls.
func (c *Client) Enabled() bool { return c != nil && c.APIKey != "" }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// complete sends one system + user exchange and returns the reply text.
func (c *Client) complete(ctx context.Context, system, user string, maxTokens int) (string, error) {
	if !c.Enabled() {
		return "", ErrDisabled
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	model := c.Model
	if model == "" {
		model = DefaultModel
	}
	body, err := json.Marshal(chatRequest{
		Model:       model,
		Messages:    []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
		MaxTokens:   maxTokens,
		Temperature: 0.2,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 90 * time.Second}
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai gateway: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("ai gateway: %w", err)
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("ai gateway: %s: unexpected response", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		msg := resp.Status
		if out.Error != nil && out.Error.Message != "" {
			msg = out.Error.Message
		}
		return "", fmt.Errorf("ai gateway: %s", msg)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("ai gateway: empty response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

// Answer is a model reply plus the exact redacted data that was sent, so
// users can see what left the process.
type Answer struct {
	Text  string `json:"text"`
	Model string `json:"model"`
	Sent  any    `json:"sent"`
}

const systemPrompt = `You are a security assistant inside Scout, a self-hosted vulnerability scanner for developers.
Scout's deterministic remediation is the source of truth; you add context, never contradict it without saying why.
Values such as <host>, <ip>, <email>, <token> and <redacted> were masked before reaching you: never ask for them or guess them.
Be concise and concrete. Use short Markdown sections. Do not invent findings that are not in the data.`

func (c *Client) model() string {
	if c.Model == "" {
		return DefaultModel
	}
	return c.Model
}

// Explain describes one finding in context and suggests how to fix it for
// the detected stacks.
func (c *Client) Explain(ctx context.Context, f core.Finding, stacks []string) (Answer, error) {
	payload := struct {
		Finding RedactedFinding `json:"finding"`
		Stacks  []string        `json:"detected_stacks,omitempty"`
	}{Finding(f), stacks}
	data, _ := json.MarshalIndent(payload, "", "  ")
	user := "Explain this finding for the developer who must fix it:\n" +
		"1. What it means and a realistic attack scenario (2-4 sentences).\n" +
		"2. How to confirm it is real.\n" +
		"3. A concrete fix for the detected stacks (or common stacks if none), with a short code or config snippet.\n" +
		"4. How to verify the fix.\n\nFinding (JSON):\n" + string(data)
	text, err := c.complete(ctx, systemPrompt, user, 1200)
	return Answer{Text: text, Model: c.model(), Sent: payload}, err
}

// TargetSummary is the redacted per-target input to a stakeholder summary.
type TargetSummary struct {
	Target      string            `json:"target"` // the configured target name, not its URL
	Environment string            `json:"environment"`
	Grade       string            `json:"grade"`
	Score       float64           `json:"score"`
	Open        map[string]int    `json:"open_by_severity"`
	Caps        []string          `json:"grade_caps,omitempty"`
	TopFixes    []RedactedFinding `json:"top_fixes,omitempty"`
}

// Summarize writes a short, non-technical summary of the latest scans.
func (c *Client) Summarize(ctx context.Context, scans []core.ScanResult, opts scoring.Options) (Answer, error) {
	var targets []TargetSummary
	for _, sc := range scans {
		o := opts
		o.Assessed = sc.Assessed
		r := scoring.Score(sc.Findings, o)
		ts := TargetSummary{Target: sc.Target.Name, Environment: string(sc.Target.Environment), Grade: r.Grade, Score: r.Score, Open: map[string]int{}}
		for _, cp := range r.Caps {
			ts.Caps = append(ts.Caps, cp.Reason)
		}
		byFP := map[string]core.Finding{}
		for _, f := range sc.Findings {
			byFP[f.Fingerprint] = f
			if scoring.Counts(f) {
				ts.Open[f.Severity.String()]++
			}
		}
		for i, it := range scoring.FixNext(sc.Findings, o) {
			if i == 5 {
				break
			}
			ts.TopFixes = append(ts.TopFixes, Finding(byFP[it.Fingerprint]))
		}
		targets = append(targets, ts)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Target < targets[j].Target })
	data, _ := json.MarshalIndent(targets, "", "  ")
	user := "Write a short security summary for a non-technical stakeholder (a manager or client):\n" +
		"- Overall posture in one or two sentences, using the grades.\n" +
		"- The most important risks in plain language (no jargon, no code).\n" +
		"- What the team should do next, in priority order.\n" +
		"Keep it under 250 words.\n\nScan data (JSON):\n" + string(data)
	text, err := c.complete(ctx, systemPrompt, user, 800)
	return Answer{Text: text, Model: c.model(), Sent: targets}, err
}
