package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/remediation"
)

func (s *Server) aiStatus(c *gin.Context) {
	if !s.d.AI.Enabled() {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	model := s.d.AI.Model
	if model == "" {
		model = "default"
	}
	c.JSON(http.StatusOK, gin.H{"enabled": true, "model": model, "provider": "Vercel AI Gateway"})
}

// aiExplain explains one finding from the latest scans. Only the redacted
// finding is sent; the response includes exactly what was sent.
func (s *Server) aiExplain(c *gin.Context) {
	if !s.d.AI.Enabled() {
		fail(c, http.StatusNotFound, "AI is not configured")
		return
	}
	ctx := c.Request.Context()
	scans, err := s.latestScans(ctx)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	fp := c.Param("fingerprint")
	for _, sc := range scans {
		for _, f := range sc.Findings {
			if f.Fingerprint != fp {
				continue
			}
			stacks := remediation.DetectStacks(f.Evidence.Response, len(sc.Target.Routes) > 0)
			ans, err := s.d.AI.Explain(ctx, f, stacks)
			if err != nil {
				fail(c, http.StatusBadGateway, err.Error())
				return
			}
			s.d.Logger.Info("ai explanation", "user", c.GetString(ctxUserKey), "check", f.CheckID, "model", ans.Model)
			c.JSON(http.StatusOK, ans)
			return
		}
	}
	fail(c, http.StatusNotFound, "finding not found in any latest scan")
}

// aiSummary writes a stakeholder summary of every target's latest scan.
func (s *Server) aiSummary(c *gin.Context) {
	if !s.d.AI.Enabled() {
		fail(c, http.StatusNotFound, "AI is not configured")
		return
	}
	ctx := c.Request.Context()
	scans, err := s.latestScans(ctx)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	if len(scans) == 0 {
		fail(c, http.StatusBadRequest, "there are no scans to summarize")
		return
	}
	ans, err := s.d.AI.Summarize(ctx, scans, s.d.Scoring)
	if err != nil {
		fail(c, http.StatusBadGateway, err.Error())
		return
	}
	s.d.Logger.Info("ai stakeholder summary", "user", c.GetString(ctxUserKey), "model", ans.Model)
	c.JSON(http.StatusOK, ans)
}
