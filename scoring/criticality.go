package scoring

import (
	"strings"

	"github.com/MUKE-coder/scout/core"
)

// CriticalityRule sets how much an asset matters. Examples: a payments API
// at 1.5, a marketing site at 0.7.
type CriticalityRule struct {
	// Host is an exact host or "*.example.com"; empty matches any host.
	Host string `json:"host,omitempty" yaml:"host"`
	// PathPrefix narrows the rule to paths under it; empty matches any path.
	PathPrefix string  `json:"path_prefix,omitempty" yaml:"path_prefix"`
	Value      float64 `json:"value" yaml:"value"`
}

func (r CriticalityRule) matches(a core.Asset) bool {
	if r.Host != "" && !(core.Scope{Hosts: []string{r.Host}}).AllowsHost(a.Host) {
		return false
	}
	return r.PathPrefix == "" || strings.HasPrefix(a.Path, r.PathPrefix)
}

// criticality resolves an asset's multiplier: the asset's own value, else
// the first matching rule, else 1.
func (o Options) criticality(a core.Asset) float64 {
	if a.Criticality > 0 {
		return a.Criticality
	}
	for _, r := range o.Criticality {
		if r.Value > 0 && r.matches(a) {
			return r.Value
		}
	}
	return 1.0
}

// risk is Risk with the options' criticality rules applied.
func (o Options) risk(f core.Finding) float64 {
	return SeverityBase[f.Severity] * ConfidenceFactor[f.Confidence] *
		ExposureFactor(f.Asset.Exposure) * o.criticality(f.Asset)
}
