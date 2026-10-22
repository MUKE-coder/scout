// Package scoring turns findings into a 0-100 score, a letter grade,
// per-category subscores and the "fix next" ranking. It is deterministic:
// the same findings and options always produce the same report.
package scoring

import (
	"math"
	"sort"

	"github.com/MUKE-coder/scout/core"
)

// DefaultK is the decay constant: a category's score is 100·e^(−Σrisk/K).
// With K = 50 one confirmed internet-facing critical (risk 40) leaves a
// category at 45, one high at 67, one medium at 85 and one low at 96.
const DefaultK = 50.0

// DefaultWeights weight categories in the overall score; app and API
// security count most.
var DefaultWeights = map[core.Category]float64{
	core.CategoryApp:      3,
	core.CategoryAPI:      3,
	core.CategoryAuth:     3,
	core.CategoryExposure: 2,
	core.CategoryCode:     2,
	core.CategoryTLS:      1.5,
	core.CategoryConfig:   1.5,
	core.CategoryNetwork:  1.5,
	core.CategoryHost:     1.5,
	core.CategoryHeaders:  1,
	core.CategoryDNS:      1,
}

// Options tune scoring. The zero value uses the defaults.
type Options struct {
	K       float64
	Weights map[core.Category]float64
	// Assessed lists the categories the scan actually covered. Only these
	// enter the overall score, so a scan that never looked at host security
	// does not get a free 100 for it. Nil means every category with findings
	// plus every weighted category.
	Assessed []core.Category
}

func (o Options) k() float64 {
	if o.K > 0 {
		return o.K
	}
	return DefaultK
}

func (o Options) weight(c core.Category) float64 {
	w := o.Weights
	if w == nil {
		w = DefaultWeights
	}
	if v, ok := w[c]; ok {
		return v
	}
	return 1
}

// CategoryScore is one category's subscore.
type CategoryScore struct {
	Category core.Category `json:"category"`
	Score    float64       `json:"score"`
	Grade    string        `json:"grade"`
	Risk     float64       `json:"risk"`
	Findings int           `json:"findings"` // open findings counted
	// Worst is the worst open severity, used to color the subscore bar.
	Worst core.Severity `json:"worst"`
}

// Report is the scored outcome of a set of findings.
type Report struct {
	Score      float64         `json:"score"`
	Grade      string          `json:"grade"`
	Categories []CategoryScore `json:"categories"`
}

// Grade maps a score to a letter: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F.
func Grade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// Score computes the report for findings.
func Score(findings []core.Finding, opts Options) Report {
	risk := map[core.Category]float64{}
	count := map[core.Category]int{}
	worst := map[core.Category]core.Severity{}
	for _, f := range findings {
		if !Counts(f) {
			continue
		}
		risk[f.Category] += Risk(f)
		count[f.Category]++
		if f.Severity > worst[f.Category] {
			worst[f.Category] = f.Severity
		}
	}

	var cats []CategoryScore
	var weighted, totalWeight float64
	for _, c := range assessed(opts, count) {
		s := round1(100 * math.Exp(-risk[c]/opts.k()))
		cats = append(cats, CategoryScore{
			Category: c, Score: s, Grade: Grade(s),
			Risk: round1(risk[c]), Findings: count[c], Worst: worst[c],
		})
		w := opts.weight(c)
		weighted += s * w
		totalWeight += w
	}

	overall := 100.0
	if totalWeight > 0 {
		overall = round1(weighted / totalWeight)
	}
	return Report{Score: overall, Grade: Grade(overall), Categories: cats}
}

// assessed returns the categories to score, in declaration order.
func assessed(opts Options, withFindings map[core.Category]int) []core.Category {
	set := map[core.Category]bool{}
	if opts.Assessed != nil {
		for _, c := range opts.Assessed {
			set[c] = true
		}
	} else {
		w := opts.Weights
		if w == nil {
			w = DefaultWeights
		}
		for c := range w {
			set[c] = true
		}
	}
	// A category with findings is always scored, even if not listed.
	for c := range withFindings {
		set[c] = true
	}
	out := make([]core.Category, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
