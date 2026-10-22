// Package integrations connects Scout to its sibling tools, Pulse
// (observability) and Sentinel (runtime defense). Both are optional and
// auto-detected: Scout is fully useful with neither present. These clients
// talk to operator-configured sibling services, never to scan targets, so
// they do not go through the scan guard.
package integrations

import (
	"math"

	"github.com/MUKE-coder/scout/core"
)

// CombinedScore merges Scout's exposure score (how exposed the app is, from
// a scan, 0-100 where higher is safer) with Sentinel's runtime defense score
// (how well it defends at runtime, 0-100). The result is the geometric mean,
// so a weakness on either side pulls the combined number down and neither
// side can mask the other. A runtime score <= 0 means "unknown": the
// exposure score is returned unchanged.
func CombinedScore(exposure, runtime float64) float64 {
	exposure = clamp(exposure)
	if runtime <= 0 {
		return exposure
	}
	return math.Round(math.Sqrt(exposure*clamp(runtime))*10) / 10
}

func clamp(v float64) float64 {
	return math.Max(0, math.Min(100, v))
}

// ScanRef is the minimal, non-sensitive description of a scan shared with a
// sibling. It never carries findings' evidence.
type ScanRef struct {
	ID         string           `json:"id"`
	Target     string           `json:"target"`
	TargetURL  string           `json:"target_url,omitempty"`
	Env        core.Environment `json:"environment"`
	Mode       string           `json:"mode"`
	Grade      string           `json:"grade"`
	Score      float64          `json:"score"`
	Findings   int              `json:"findings"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
}

// RefOf builds a ScanRef from a scan result.
func RefOf(sc core.ScanResult) ScanRef {
	return ScanRef{
		ID:         sc.ID,
		Target:     sc.Target.Name,
		TargetURL:  sc.Target.URL,
		Env:        sc.Target.Environment,
		Mode:       sc.Mode.String(),
		Grade:      sc.Grade,
		Score:      sc.Score,
		Findings:   len(sc.Findings),
		StartedAt:  sc.StartedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		FinishedAt: sc.FinishedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}
