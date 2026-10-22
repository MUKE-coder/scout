package scoring

import "github.com/MUKE-coder/scout/core"

// SeverityBase is the base risk of each severity.
var SeverityBase = map[core.Severity]float64{
	core.SeverityCritical: 40,
	core.SeverityHigh:     20,
	core.SeverityMedium:   8,
	core.SeverityLow:      2,
	core.SeverityInfo:     0,
}

// ConfidenceFactor scales risk by how sure Scout is.
var ConfidenceFactor = map[core.Confidence]float64{
	core.ConfidenceConfirmed: 1.0,
	core.ConfidenceLikely:    0.7,
	core.ConfidencePossible:  0.4,
}

// ExposureFactor scales risk by who can reach the asset. An unknown exposure
// counts as internet-facing: when unsure, assume the worst.
func ExposureFactor(e core.Exposure) float64 {
	switch e {
	case core.ExposureAuthenticated:
		return 0.6
	case core.ExposureInternal:
		return 0.4
	default:
		return 1.0
	}
}

// Criticality returns the asset's criticality multiplier, defaulting to 1.
func Criticality(a core.Asset) float64 {
	if a.Criticality > 0 {
		return a.Criticality
	}
	return 1.0
}

// Risk is a finding's weight:
// severity_base × confidence × exposure × asset_criticality.
func Risk(f core.Finding) float64 {
	return SeverityBase[f.Severity] * ConfidenceFactor[f.Confidence] *
		ExposureFactor(f.Asset.Exposure) * Criticality(f.Asset)
}

// Counts reports whether a finding contributes to the score: only open
// findings do. Fixed, accepted-risk and false-positive findings are ignored.
func Counts(f core.Finding) bool {
	return f.Status == "" || f.Status == core.StatusOpen
}
