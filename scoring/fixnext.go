package scoring

import (
	"sort"

	"github.com/MUKE-coder/scout/core"
)

// EffortHours is the relative cost of each effort size. A missing effort
// counts as medium.
var EffortHours = map[core.Effort]float64{core.EffortS: 1, core.EffortM: 3, core.EffortL: 8}

// FixItem is one entry in the "fix next" list.
type FixItem struct {
	Fingerprint string        `json:"fingerprint"`
	CheckID     string        `json:"check_id"`
	Title       string        `json:"title"`
	Severity    core.Severity `json:"severity"`
	Asset       string        `json:"asset"`
	Effort      core.Effort   `json:"effort"`
	// Points is how much the overall score rises if this alone is fixed:
	// the larger of the capped gain (lifting a cap) and the uncapped gain.
	// Using the uncapped gain too keeps findings rankable while a cap from
	// another finding holds the capped score flat.
	Points float64 `json:"points"`
	// Priority is Points per effort hour: the safety bought per hour.
	Priority float64 `json:"priority"`
}

// FixNext ranks open findings by points regained per effort hour, highest
// first. Ties break on severity, then fingerprint, so order is stable.
func FixNext(findings []core.Finding, opts Options) []FixItem {
	base := Score(findings, opts)
	var items []FixItem
	for i, f := range findings {
		if !Counts(f) {
			continue
		}
		without := make([]core.Finding, 0, len(findings)-1)
		without = append(without, findings[:i]...)
		without = append(without, findings[i+1:]...)
		after := Score(without, opts)
		points := round1(max(after.Score-base.Score, after.Uncapped-base.Uncapped))

		effort := f.Remediation.Effort
		hours, ok := EffortHours[effort]
		if !ok {
			effort, hours = core.EffortM, EffortHours[core.EffortM]
		}
		items = append(items, FixItem{
			Fingerprint: f.Fingerprint, CheckID: f.CheckID, Title: f.Title, Severity: f.Severity,
			Asset: f.Asset.Value, Effort: effort, Points: points, Priority: round2(points / hours),
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Fingerprint < b.Fingerprint
	})
	return items
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }
