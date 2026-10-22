package report

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// SARIF 2.1.0 types: only the fields GitHub Code Scanning reads.
type (
	sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription sarifText      `json:"shortDescription"`
		FullDescription  sarifText      `json:"fullDescription"`
		Help             sarifHelp      `json:"help"`
		Properties       map[string]any `json:"properties"`
	}
	sarifText struct {
		Text string `json:"text"`
	}
	sarifHelp struct {
		Text     string `json:"text"`
		Markdown string `json:"markdown"`
	}
	sarifResult struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             sarifText         `json:"message"`
		Locations           []sarifLocation   `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties,omitempty"`
	}
	sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	sarifArtifact struct {
		URI string `json:"uri"`
	}
	sarifRegion struct {
		StartLine int `json:"startLine"`
	}
)

// SARIFLevel maps a severity to a SARIF result level.
func SARIFLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	}
	return "note"
}

// securitySeverity is GitHub's 0-10 score: >= 9 critical, >= 7 high,
// >= 4 medium, else low.
func securitySeverity(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "9.5"
	case core.SeverityHigh:
		return "8.0"
	case core.SeverityMedium:
		return "5.5"
	case core.SeverityLow:
		return "3.0"
	}
	return "0.0"
}

// SARIF writes open findings from every result as one SARIF run.
func SARIF(w io.Writer, version string, results []Result) error {
	rules := map[string]sarifRule{}
	var out []sarifResult
	for _, r := range results {
		for _, f := range SortFindings(r.Scan.Findings) {
			if !scoring.Counts(f) {
				continue
			}
			if existing, ok := rules[f.CheckID]; !ok || worseSeverity(f, existing) {
				rules[f.CheckID] = ruleFor(f)
			}
			out = append(out, resultFor(f))
		}
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	driverRules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		driverRules = append(driverRules, rules[id])
	}
	if out == nil {
		out = []sarifResult{}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Scout", Version: version,
				InformationURI: "https://github.com/MUKE-coder/scout",
				Rules:          driverRules,
			}},
			Results: out,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func worseSeverity(f core.Finding, r sarifRule) bool {
	cur, _ := strconv.ParseFloat(r.Properties["security-severity"].(string), 64)
	next, _ := strconv.ParseFloat(securitySeverity(f.Severity), 64)
	return next > cur
}

func ruleFor(f core.Finding) sarifRule {
	tags := []string{"security", f.Category.String()}
	tags = append(tags, f.CWE...)
	what := f.Remediation.What
	if what == "" {
		what = f.Title
	}
	var help strings.Builder
	help.WriteString(what)
	if f.Remediation.Why != "" {
		help.WriteString("\n\n" + f.Remediation.Why)
	}
	return sarifRule{
		ID:               f.CheckID,
		Name:             f.CheckID,
		ShortDescription: sarifText{Text: f.Title},
		FullDescription:  sarifText{Text: what},
		Help:             sarifHelp{Text: help.String(), Markdown: help.String()},
		Properties:       map[string]any{"tags": tags, "security-severity": securitySeverity(f.Severity)},
	}
}

func resultFor(f core.Finding) sarifResult {
	loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Asset.Value}}
	if f.Asset.Kind == core.AssetFile && f.Asset.File != "" {
		loc.ArtifactLocation.URI = f.Asset.File
		if f.Asset.Line > 0 {
			loc.Region = &sarifRegion{StartLine: f.Asset.Line}
		}
	}
	msg := f.Title
	if f.Asset.Value != "" && f.Asset.Kind != core.AssetFile {
		msg += " (" + f.Asset.Value + ")"
	}
	return sarifResult{
		RuleID:              f.CheckID,
		Level:               SARIFLevel(f.Severity),
		Message:             sarifText{Text: msg},
		Locations:           []sarifLocation{{PhysicalLocation: loc}},
		PartialFingerprints: map[string]string{"scoutFingerprint/v1": f.Fingerprint},
		Properties:          map[string]any{"severity": f.Severity.String(), "confidence": f.Confidence.String(), "owasp": f.OWASP},
	}
}
