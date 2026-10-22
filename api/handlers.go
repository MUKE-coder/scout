package api

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/report"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

// latestScans returns the newest full scan of every target that has one,
// ordered by target name.
func (s *Server) latestScans(ctx context.Context) ([]core.ScanResult, error) {
	all, err := s.d.Store.ListScans(ctx, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []core.ScanResult
	for _, sc := range all { // newest first
		if seen[sc.Target.Name] {
			continue
		}
		seen[sc.Target.Name] = true
		full, err := s.d.Store.GetScan(ctx, sc.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, full)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target.Name < out[j].Target.Name })
	return out, nil
}

// previousScan returns the scan of the same target before sc, if any.
func (s *Server) previousScan(ctx context.Context, sc core.ScanResult) (core.ScanResult, bool) {
	all, err := s.d.Store.ListScans(ctx, 0)
	if err != nil {
		return core.ScanResult{}, false
	}
	for _, other := range all { // newest first
		if other.Target.Name == sc.Target.Name && other.StartedAt.Before(sc.StartedAt) {
			full, err := s.d.Store.GetScan(ctx, other.ID)
			return full, err == nil
		}
	}
	return core.ScanResult{}, false
}

// seenBefore reports whether a fingerprint appeared in a scan that ended
// before the cutoff.
func (s *Server) seenBefore(ctx context.Context, cutoff time.Time) func(string) bool {
	return func(fp string) bool {
		fs, err := s.d.Store.ListFindings(ctx, storage.FindingFilter{Fingerprint: fp})
		if err != nil {
			return false
		}
		for _, f := range fs {
			if !f.LastSeen.IsZero() && f.LastSeen.Before(cutoff) {
				return true
			}
		}
		return false
	}
}

// --- overview ---

type severityCounts map[string]int

func countOpen(fs []core.Finding) severityCounts {
	out := severityCounts{}
	for _, f := range fs {
		if scoring.Counts(f) {
			out[f.Severity.String()]++
		}
	}
	return out
}

type trendPoint struct {
	At    time.Time `json:"at"`
	Score float64   `json:"score"`
	Grade string    `json:"grade"`
}

type targetOverview struct {
	Target  core.Target       `json:"target"`
	ScanID  string            `json:"scan_id"`
	At      time.Time         `json:"at"`
	Mode    core.Mode         `json:"mode"`
	Report  scoring.Report    `json:"report"`
	FixNext []scoring.FixItem `json:"fix_next"`
	Open    severityCounts    `json:"open"`
	Trend   []trendPoint      `json:"trend"`
}

func (s *Server) overview(c *gin.Context) {
	ctx := c.Request.Context()
	latest, err := s.latestScans(ctx)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	all, err := s.d.Store.ListScans(ctx, 0)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	since := time.Now().Add(-30 * 24 * time.Hour)
	out := make([]targetOverview, 0, len(latest))
	for _, sc := range latest {
		r := report.Build(sc, s.d.Scoring)
		top := r.FixNext
		if len(top) > 5 {
			top = top[:5]
		}
		var trend []trendPoint
		for i := len(all) - 1; i >= 0; i-- { // oldest first
			h := all[i]
			if h.Target.Name == sc.Target.Name && h.StartedAt.After(since) && h.Grade != "" {
				trend = append(trend, trendPoint{At: h.StartedAt, Score: h.Score, Grade: h.Grade})
			}
		}
		out = append(out, targetOverview{
			Target: sc.Target, ScanID: sc.ID, At: sc.StartedAt, Mode: sc.Mode,
			Report: r.Report, FixNext: top, Open: countOpen(sc.Findings), Trend: trend,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"app":         s.d.Settings.AppName,
		"environment": s.d.Settings.Environment,
		"targets":     out,
		"configured":  s.d.Settings.Targets,
		"killed":      s.d.Kill.Killed(),
	})
}

// --- scans ---

func (s *Server) listScans(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	scans, err := s.d.Store.ListScans(c.Request.Context(), limit)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

func (s *Server) getScan(c *gin.Context) {
	sc, err := s.d.Store.GetScan(c.Request.Context(), c.Param("id"))
	if errors.Is(err, storage.ErrNotFound) {
		fail(c, http.StatusNotFound, "scan not found")
		return
	} else if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, report.Build(sc, s.d.Scoring))
}

type startScanRequest struct {
	Target string `json:"target" binding:"required"` // a configured target name or URL
	Mode   string `json:"mode"`
}

// findTarget resolves a configured target by name or URL. Only configured
// targets can be scanned from the dashboard, so the API cannot be used to
// point Scout at arbitrary hosts.
func (s *Server) findTarget(ref string) (core.Target, bool) {
	for _, t := range s.d.Settings.Targets {
		if t.Name == ref || t.URL == ref {
			return t, true
		}
	}
	return core.Target{}, false
}

func (s *Server) startScan(c *gin.Context) {
	var req startScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "target is required")
		return
	}
	t, ok := s.findTarget(req.Target)
	if !ok {
		fail(c, http.StatusBadRequest, "unknown target: add it to the targets in scout.yaml first")
		return
	}
	mode := s.d.Settings.Mode
	if req.Mode != "" {
		m, err := core.ParseMode(req.Mode)
		if err != nil {
			fail(c, http.StatusBadRequest, err.Error())
			return
		}
		mode = m
	}
	if s.d.Kill.Killed() {
		fail(c, http.StatusConflict, "kill switch is engaged; resume first")
		return
	}
	id := engine.NewScanID()
	s.d.Go(func(ctx context.Context) {
		if _, err := s.d.Engine.Run(ctx, engine.Request{Target: t, Mode: mode, ID: id}); err != nil {
			s.d.Logger.Error("dashboard scan failed", "scan", id, "err", err)
			s.tracker.failed(id, err)
		}
	})
	c.JSON(http.StatusAccepted, gin.H{"id": id})
}

func (s *Server) runningScans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"scans": s.tracker.snapshot()})
}

// --- findings ---

type findingRow struct {
	core.Finding
	Target string `json:"target"`
	ScanID string `json:"scan_id"`
	Change string `json:"change"` // new | regressed | unchanged
}

func (s *Server) listFindings(c *gin.Context) {
	ctx := c.Request.Context()
	var scans []core.ScanResult
	if id := c.Query("scan"); id != "" {
		sc, err := s.d.Store.GetScan(ctx, id)
		if err != nil {
			fail(c, http.StatusNotFound, "scan not found")
			return
		}
		scans = []core.ScanResult{sc}
	} else {
		var err error
		if scans, err = s.latestScans(ctx); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	sev, cat := c.Query("severity"), c.Query("category")
	status, change, target := c.Query("status"), c.Query("change"), c.Query("target")
	q := strings.ToLower(c.Query("q"))

	rows := []findingRow{}
	for _, sc := range scans {
		if target != "" && sc.Target.Name != target {
			continue
		}
		changes := map[string]string{}
		if prev, ok := s.previousScan(ctx, sc); ok {
			d := report.DiffScans(prev, sc, s.seenBefore(ctx, prev.StartedAt))
			for _, f := range d.New {
				changes[f.Fingerprint] = "new"
			}
			for _, f := range d.Regressed {
				changes[f.Fingerprint] = "regressed"
			}
		} else {
			for _, f := range sc.Findings {
				changes[f.Fingerprint] = "new"
			}
		}
		for _, f := range report.SortFindings(sc.Findings) {
			ch := changes[f.Fingerprint]
			if ch == "" {
				ch = "unchanged"
			}
			switch {
			case sev != "" && f.Severity.String() != sev,
				cat != "" && f.Category.String() != cat,
				status != "" && string(f.Status) != status,
				change != "" && ch != change,
				q != "" && !strings.Contains(strings.ToLower(f.Title+" "+f.Asset.Value+" "+f.CheckID), q):
				continue
			}
			rows = append(rows, findingRow{Finding: f, Target: sc.Target.Name, ScanID: sc.ID, Change: ch})
		}
	}
	c.JSON(http.StatusOK, gin.H{"findings": rows})
}

type historyEntry struct {
	ScanID   string        `json:"scan_id"`
	At       time.Time     `json:"at"`
	Severity core.Severity `json:"severity"`
	Status   core.Status   `json:"status"`
}

func (s *Server) getFinding(c *gin.Context) {
	ctx := c.Request.Context()
	fp := c.Param("fingerprint")
	scans, err := s.d.Store.ListScans(ctx, 0)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	var (
		latest  *findingRow
		history []historyEntry
	)
	for _, meta := range scans { // newest first
		sc, err := s.d.Store.GetScan(ctx, meta.ID)
		if err != nil {
			continue
		}
		for _, f := range sc.Findings {
			if f.Fingerprint != fp {
				continue
			}
			if latest == nil {
				latest = &findingRow{Finding: f, Target: sc.Target.Name, ScanID: sc.ID}
			}
			history = append(history, historyEntry{ScanID: sc.ID, At: sc.StartedAt, Severity: f.Severity, Status: f.Status})
		}
	}
	if latest == nil {
		fail(c, http.StatusNotFound, "finding not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{"finding": latest, "history": history})
}

type statusRequest struct {
	Fingerprints []string    `json:"fingerprints" binding:"required"`
	Status       core.Status `json:"status" binding:"required"`
}

// setStatus updates findings' status in each target's latest scan, which is
// what the next scan carries forward (accepted-risk and false-positive).
func (s *Server) setStatus(c *gin.Context) {
	var req statusRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Fingerprints) == 0 {
		fail(c, http.StatusBadRequest, "fingerprints and status are required")
		return
	}
	switch req.Status {
	case core.StatusOpen, core.StatusFixed, core.StatusAcceptedRisk, core.StatusFalsePositive:
	default:
		fail(c, http.StatusBadRequest, "status must be open, fixed, accepted-risk or false-positive")
		return
	}
	ctx := c.Request.Context()
	want := map[string]bool{}
	for _, fp := range req.Fingerprints {
		want[fp] = true
	}
	scans, err := s.latestScans(ctx)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	updated := 0
	for _, sc := range scans {
		changed := false
		for i := range sc.Findings {
			if want[sc.Findings[i].Fingerprint] {
				sc.Findings[i].Status = req.Status
				changed = true
				updated++
			}
		}
		if !changed {
			continue
		}
		r := scoring.Score(sc.Findings, withAssessed(s.d.Scoring, sc))
		sc.Score, sc.Grade = r.Score, r.Grade
		if err := s.d.Store.SaveScan(ctx, sc); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"updated": updated})
}

func withAssessed(o scoring.Options, sc core.ScanResult) scoring.Options {
	o.Assessed = sc.Assessed
	return o
}

// verify re-runs just the finding's check against its target, without
// saving a new scan. If the finding is gone it is marked fixed.
func (s *Server) verify(c *gin.Context) {
	ctx := c.Request.Context()
	fp := c.Param("fingerprint")
	scans, err := s.latestScans(ctx)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	for _, sc := range scans {
		for i, f := range sc.Findings {
			if f.Fingerprint != fp {
				continue
			}
			res, err := s.d.Engine.Run(ctx, engine.Request{
				Target: sc.Target, Mode: sc.Mode, Checks: []string{f.CheckID}, Ephemeral: true,
			})
			if err != nil {
				fail(c, http.StatusConflict, err.Error())
				return
			}
			if len(res.Errors) > 0 {
				c.JSON(http.StatusOK, gin.H{"fixed": false, "error": res.Errors[0].Error})
				return
			}
			still := false
			for _, nf := range res.Findings {
				if nf.Fingerprint == fp {
					still = true
				}
			}
			if !still {
				sc.Findings[i].Status = core.StatusFixed
				r := scoring.Score(sc.Findings, withAssessed(s.d.Scoring, sc))
				sc.Score, sc.Grade = r.Score, r.Grade
				if err := s.d.Store.SaveScan(ctx, sc); err != nil {
					fail(c, http.StatusInternalServerError, err.Error())
					return
				}
			}
			c.JSON(http.StatusOK, gin.H{"fixed": !still, "checked_at": res.FinishedAt})
			return
		}
	}
	fail(c, http.StatusNotFound, "finding not found in any latest scan")
}

// --- control & settings ---

func (s *Server) status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"killed": s.d.Kill.Killed(), "running": s.tracker.snapshot()})
}

func (s *Server) kill(c *gin.Context) {
	s.d.Kill.Kill()
	s.d.Logger.Warn("kill switch engaged from the dashboard", "user", c.GetString(ctxUserKey))
	c.JSON(http.StatusOK, gin.H{"killed": true})
}

func (s *Server) resume(c *gin.Context) {
	s.d.Kill.Resume()
	s.d.Logger.Info("kill switch released from the dashboard", "user", c.GetString(ctxUserKey))
	c.JSON(http.StatusOK, gin.H{"killed": false})
}

func (s *Server) settings(c *gin.Context) {
	c.JSON(http.StatusOK, s.d.Settings)
}

// export downloads the latest findings as JSON or CSV.
func (s *Server) export(c *gin.Context) {
	scans, err := s.latestScans(c.Request.Context())
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	switch c.DefaultQuery("format", "json") {
	case "json":
		results := make([]report.Result, 0, len(scans))
		for _, sc := range scans {
			results = append(results, report.Build(sc, s.d.Scoring))
		}
		c.Header("Content-Disposition", `attachment; filename="scout-`+stamp+`.json"`)
		c.Header("Content-Type", "application/json")
		_ = report.JSON(c.Writer, s.d.Settings.Version, results)
	case "csv":
		c.Header("Content-Disposition", `attachment; filename="scout-`+stamp+`.csv"`)
		c.Header("Content-Type", "text/csv")
		w := csv.NewWriter(c.Writer)
		_ = w.Write([]string{"target", "severity", "confidence", "category", "status", "check_id", "title", "asset", "fingerprint", "first_seen", "last_seen", "cwe", "owasp"})
		for _, sc := range scans {
			for _, f := range report.SortFindings(sc.Findings) {
				_ = w.Write([]string{sc.Target.Name, f.Severity.String(), f.Confidence.String(), f.Category.String(),
					string(f.Status), f.CheckID, csvSafe(f.Title), csvSafe(f.Asset.Value), f.Fingerprint,
					f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339),
					strings.Join(f.CWE, " "), strings.Join(f.OWASP, " ")})
			}
		}
		w.Flush()
	default:
		fail(c, http.StatusBadRequest, "format must be json or csv")
	}
}

// csvSafe neutralizes spreadsheet formula injection in scanned-site text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
