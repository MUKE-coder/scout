package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Paths on the sibling services. The Pulse path is from Scout's project
// description; both are overridable in config to match a deployment.
const (
	DefaultPulseTestRuns = "/pulse/api/test-runs"
	DefaultSentinelScore = "/sentinel/api/security-score"
	// Health paths probed for auto-detection.
	pulseHealth    = "/pulse/api/health"
	sentinelHealth = "/sentinel/api/health"
)

// doer is the subset of *http.Client the clients use; tests supply their own.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}

func newHTTP() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// detect probes a health path and reports whether the sibling is reachable.
func detect(ctx context.Context, h doer, base, healthPath string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+healthPath, nil)
	if err != nil {
		return false
	}
	resp, err := h.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode < 500 // present, even if it needs auth
}

func postJSON(ctx context.Context, h doer, url, token string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Scout-Integrations/1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return nil
}

// Pulse registers scans with Pulse so they appear as bands on its charts.
type Pulse struct {
	BaseURL  string
	Path     string
	Token    string
	HTTP     doer
	detected bool
}

// NewPulse returns a Pulse client.
func NewPulse(baseURL, path, token string) *Pulse {
	if path == "" {
		path = DefaultPulseTestRuns
	}
	return &Pulse{BaseURL: strings.TrimRight(baseURL, "/"), Path: path, Token: token, HTTP: newHTTP()}
}

// Detect probes Pulse and remembers the result.
func (p *Pulse) Detect(ctx context.Context) bool {
	p.detected = p.BaseURL != "" && detect(ctx, p.HTTP, p.BaseURL, pulseHealth)
	return p.detected
}

// Available reports whether Pulse was detected.
func (p *Pulse) Available() bool { return p != nil && p.detected }

// pulseTestRun is Scout's documented payload for /pulse/api/test-runs: a
// labeled time span Pulse can overlay on its latency and RPS charts.
type pulseTestRun struct {
	Source    string  `json:"source"` // always "scout"
	Kind      string  `json:"kind"`   // "security-scan"
	Label     string  `json:"label"`
	ScanID    string  `json:"scan_id"`
	Target    string  `json:"target"`
	StartedAt string  `json:"started_at"`
	EndedAt   string  `json:"ended_at"`
	Grade     string  `json:"grade"`
	Score     float64 `json:"score"`
	Findings  int     `json:"findings"`
}

// RegisterScan tells Pulse about a finished scan.
func (p *Pulse) RegisterScan(ctx context.Context, ref ScanRef) error {
	return postJSON(ctx, p.HTTP, p.BaseURL+p.Path, p.Token, pulseTestRun{
		Source: "scout", Kind: "security-scan",
		Label:  fmt.Sprintf("Scout %s scan of %s", ref.Mode, ref.Target),
		ScanID: ref.ID, Target: ref.Target,
		StartedAt: ref.StartedAt, EndedAt: ref.FinishedAt,
		Grade: ref.Grade, Score: ref.Score, Findings: ref.Findings,
	})
}

// Sentinel receives Scout's exposure score to combine with its runtime
// defense score.
type Sentinel struct {
	BaseURL  string
	Path     string
	Token    string
	HTTP     doer
	detected bool
}

// NewSentinel returns a Sentinel client.
func NewSentinel(baseURL, path, token string) *Sentinel {
	if path == "" {
		path = DefaultSentinelScore
	}
	return &Sentinel{BaseURL: strings.TrimRight(baseURL, "/"), Path: path, Token: token, HTTP: newHTTP()}
}

// Detect probes Sentinel and remembers the result.
func (s *Sentinel) Detect(ctx context.Context) bool {
	s.detected = s.BaseURL != "" && detect(ctx, s.HTTP, s.BaseURL, sentinelHealth)
	return s.detected
}

// Available reports whether Sentinel was detected.
func (s *Sentinel) Available() bool { return s != nil && s.detected }

// sentinelScore is Scout's documented payload for the shared security score.
type sentinelScore struct {
	Source    string  `json:"source"` // always "scout"
	Target    string  `json:"target"`
	ScanID    string  `json:"scan_id"`
	Exposure  float64 `json:"exposure_score"` // Scout's score, higher is safer
	Grade     string  `json:"grade"`
	UpdatedAt string  `json:"updated_at"`
}

// PushScore sends Scout's exposure score for a target to Sentinel.
func (s *Sentinel) PushScore(ctx context.Context, ref ScanRef) error {
	return postJSON(ctx, s.HTTP, s.BaseURL+s.Path, s.Token, sentinelScore{
		Source: "scout", Target: ref.Target, ScanID: ref.ID,
		Exposure: ref.Score, Grade: ref.Grade,
		UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}
