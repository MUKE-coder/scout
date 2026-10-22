package core

import (
	"fmt"
	"strings"
)

// enumText maps an integer enum to its canonical lowercase name and back. It
// keeps JSON, YAML, CLI flags and the database speaking the same strings.
type enumText[T ~int] struct {
	kind  string
	names []string
}

func (e enumText[T]) String(v T) string {
	if int(v) >= 0 && int(v) < len(e.names) {
		return e.names[v]
	}
	return fmt.Sprintf("%s(%d)", e.kind, int(v))
}

func (e enumText[T]) Parse(s string) (T, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range e.names {
		if n == s {
			return T(i), nil
		}
	}
	return 0, fmt.Errorf("unknown %s %q (want one of %s)", e.kind, s, strings.Join(e.names, ", "))
}

// Severity is how bad a finding is. Ordered so that a larger value is worse.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityText = enumText[Severity]{"severity", []string{"info", "low", "medium", "high", "critical"}}

func (s Severity) String() string                { return severityText.String(s) }
func (s Severity) MarshalText() ([]byte, error)  { return []byte(s.String()), nil }
func (s *Severity) UnmarshalText(b []byte) error { return parseInto(s, severityText, b) }
func ParseSeverity(v string) (Severity, error)   { return severityText.Parse(v) }

// Confidence is how sure Scout is that a finding is real.
type Confidence int

const (
	ConfidencePossible Confidence = iota
	ConfidenceLikely
	ConfidenceConfirmed
)

var confidenceText = enumText[Confidence]{"confidence", []string{"possible", "likely", "confirmed"}}

func (c Confidence) String() string                { return confidenceText.String(c) }
func (c Confidence) MarshalText() ([]byte, error)  { return []byte(c.String()), nil }
func (c *Confidence) UnmarshalText(b []byte) error { return parseInto(c, confidenceText, b) }
func ParseConfidence(v string) (Confidence, error) { return confidenceText.Parse(v) }

// Mode is how aggressive a check is. Every check declares the most aggressive
// mode it uses; every environment caps the mode it will run.
type Mode int

const (
	// ModePassive reads headers, TLS, DNS, config and route tables. No attack traffic.
	ModePassive Mode = iota
	// ModeSafe sends harmless probes: canaries, GET-only fuzzing, version checks.
	ModeSafe
	// ModeActive sends real injection payloads and auth-bypass attempts.
	ModeActive
	// ModeIntrusive brute forces, load tests and sends state-changing requests.
	ModeIntrusive
)

var modeText = enumText[Mode]{"mode", []string{"passive", "safe", "active", "intrusive"}}

func (m Mode) String() string                { return modeText.String(m) }
func (m Mode) MarshalText() ([]byte, error)  { return []byte(m.String()), nil }
func (m *Mode) UnmarshalText(b []byte) error { return parseInto(m, modeText, b) }
func ParseMode(v string) (Mode, error)       { return modeText.Parse(v) }

// Category groups checks and drives per-category subscores.
type Category int

const (
	CategoryApp Category = iota
	CategoryAPI
	CategoryAuth
	CategoryTLS
	CategoryHeaders
	CategoryExposure
	CategoryNetwork
	CategoryDNS
	CategoryHost
	CategoryCode
	CategoryConfig
)

var categoryText = enumText[Category]{"category", []string{
	"app", "api", "auth", "tls", "headers", "exposure", "network", "dns", "host", "code", "config",
}}

// Categories returns every category in declaration order.
func Categories() []Category {
	out := make([]Category, len(categoryText.names))
	for i := range out {
		out[i] = Category(i)
	}
	return out
}

func (c Category) String() string                { return categoryText.String(c) }
func (c Category) MarshalText() ([]byte, error)  { return []byte(c.String()), nil }
func (c *Category) UnmarshalText(b []byte) error { return parseInto(c, categoryText, b) }
func ParseCategory(v string) (Category, error)   { return categoryText.Parse(v) }

// Environment is where a target runs. It caps the scan mode.
type Environment string

const (
	EnvDev     Environment = "dev"
	EnvStaging Environment = "staging"
	EnvProd    Environment = "prod"
)

// ParseEnvironment validates an environment name.
func ParseEnvironment(v string) (Environment, error) {
	switch e := Environment(strings.ToLower(strings.TrimSpace(v))); e {
	case EnvDev, EnvStaging, EnvProd:
		return e, nil
	}
	return "", fmt.Errorf("unknown environment %q (want dev, staging or prod)", v)
}

// MaxMode is the most aggressive mode an environment permits without any
// per-target opt-in.
func (e Environment) MaxMode() Mode { return e.Cap(false) }

// Cap is the most aggressive mode an environment permits. optIn is the
// explicit per-target opt-in (Target.AllowActive):
//
//	dev      Intrusive
//	staging  Active     (Intrusive with opt-in)
//	prod     Safe       (Active with opt-in; never Intrusive)
func (e Environment) Cap(optIn bool) Mode {
	switch e {
	case EnvDev:
		return ModeIntrusive
	case EnvStaging:
		if optIn {
			return ModeIntrusive
		}
		return ModeActive
	default:
		// Prod, and unknown environments treated as prod: fail safe.
		if optIn {
			return ModeActive
		}
		return ModeSafe
	}
}

// Status is where a finding sits in its lifecycle.
type Status string

const (
	StatusOpen          Status = "open"
	StatusFixed         Status = "fixed"
	StatusAcceptedRisk  Status = "accepted-risk"
	StatusFalsePositive Status = "false-positive"
)

// Effort is the rough cost of a fix: small, medium or large.
type Effort string

const (
	EffortS Effort = "S"
	EffortM Effort = "M"
	EffortL Effort = "L"
)

// Exposure is who can reach an asset.
type Exposure string

const (
	ExposureInternet      Exposure = "internet"
	ExposureAuthenticated Exposure = "authenticated"
	ExposureInternal      Exposure = "internal"
)

func parseInto[T ~int](dst *T, e enumText[T], b []byte) error {
	v, err := e.Parse(string(b))
	if err != nil {
		return err
	}
	*dst = v
	return nil
}
