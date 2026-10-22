package engine

import (
	"context"
	"errors"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

// dedupe merges findings that share a fingerprint, keeping the first one's
// evidence and the highest severity and confidence seen. Order is preserved.
func dedupe(findings []core.Finding) []core.Finding {
	index := make(map[string]int, len(findings))
	out := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		i, seen := index[f.Fingerprint]
		if !seen {
			index[f.Fingerprint] = len(out)
			out = append(out, f)
			continue
		}
		kept := &out[i]
		kept.Severity = max(kept.Severity, f.Severity)
		kept.Confidence = max(kept.Confidence, f.Confidence)
		kept.CVSS = max(kept.CVSS, f.CVSS)
	}
	return out
}

// mergeHistory stamps FirstSeen/LastSeen and carries user decisions forward
// from the previous scan of the same target. A finding the user accepted or
// marked false-positive keeps that status with its reason and expiry, unless
// the acceptance has expired, which reopens it with a note. Anything else is
// open again.
func mergeHistory(findings []core.Finding, prev []core.Finding, now time.Time) {
	byFP := make(map[string]core.Finding, len(prev))
	for _, p := range prev {
		byFP[p.Fingerprint] = p
	}
	for i := range findings {
		f := &findings[i]
		f.LastSeen = now
		f.FirstSeen = now
		f.Status = core.StatusOpen
		p, ok := byFP[f.Fingerprint]
		if !ok {
			continue
		}
		if !p.FirstSeen.IsZero() {
			f.FirstSeen = p.FirstSeen
		}
		switch {
		case p.AcceptanceExpired(now):
			f.StatusReason = "Accepted risk expired on " + p.StatusUntil.Format("2006-01-02") + " (was: " + p.StatusReason + ")"
		case p.Status == core.StatusAcceptedRisk || p.Status == core.StatusFalsePositive:
			f.Status, f.StatusReason, f.StatusUntil, f.StatusBy = p.Status, p.StatusReason, p.StatusUntil, p.StatusBy
		}
	}
}

// finish runs the findings pipeline: dedupe, merge history, score, persist,
// emit. Storage problems are recorded on the result rather than failing the
// scan.
func (e *Engine) finish(ctx context.Context, res *core.ScanResult, assessed []core.Category, persist bool) {
	res.Findings = dedupe(res.Findings)

	var prev []core.Finding
	if e.opts.Store != nil && persist {
		last, err := e.opts.Store.LatestScan(ctx, res.Target.Name)
		switch {
		case err == nil:
			prev = last.Findings
		case !errors.Is(err, storage.ErrNotFound):
			res.Errors = append(res.Errors, core.CheckError{CheckID: "storage", Error: "load previous scan: " + err.Error()})
		}
	}
	mergeHistory(res.Findings, prev, res.FinishedAt)

	res.Assessed = assessed
	opts := e.opts.Scoring
	opts.Assessed = assessed
	report := scoring.Score(res.Findings, opts)
	res.Score, res.Grade = report.Score, report.Grade

	if e.opts.Store != nil && persist {
		// Persist even if the scan was cancelled: partial results are real.
		if err := e.opts.Store.SaveScan(context.WithoutCancel(ctx), *res); err != nil {
			e.log.Error("persist scan", "scan", res.ID, "err", err)
			res.Errors = append(res.Errors, core.CheckError{CheckID: "storage", Error: "save scan: " + err.Error()})
		}
	}

	for i := range res.Findings {
		f := res.Findings[i]
		e.opts.Bus.Publish(Event{Type: EventFinding, ScanID: res.ID, Time: res.FinishedAt, CheckID: f.CheckID, Finding: &f})
	}
	summary := *res
	summary.Findings = nil
	e.opts.Bus.Publish(Event{Type: EventScanFinished, ScanID: res.ID, Time: res.FinishedAt, Count: len(res.Findings), Result: &summary})
}
