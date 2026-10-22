package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/storage"
)

// Settings is the read-only configuration the dashboard shows. It never
// carries secrets.
type Settings struct {
	AppName      string                    `json:"app_name"`
	Environment  core.Environment          `json:"environment"`
	Mode         core.Mode                 `json:"mode"`
	Targets      []core.Target             `json:"targets"`
	Scope        core.Scope                `json:"scope"`
	Criticality  []scoring.CriticalityRule `json:"criticality"`
	RateLimit    int                       `json:"rate_limit"`
	Concurrency  int                       `json:"concurrency"`
	CheckTimeout time.Duration             `json:"check_timeout_ns"`
	Retention    time.Duration             `json:"retention_ns"`
	Window       any                       `json:"window,omitempty"`
	Version      string                    `json:"version"`
}

// Deps are what the API needs. The root package wires them in, so api never
// imports it.
type Deps struct {
	Auth     *Auth
	Store    storage.Store
	Engine   *engine.Engine
	Bus      *engine.Bus
	Kill     *engine.KillSwitch
	Settings Settings
	Scoring  scoring.Options
	// Go runs background work (scans) tied to Scout's lifecycle, so shutdown
	// cancels and waits for it.
	Go     func(func(ctx context.Context))
	Logger *slog.Logger
	// Schedules lists configured schedules with next run times.
	Schedules func() any
}

// Server serves /scout/api/* and /scout/ws/live.
type Server struct {
	d       Deps
	tracker *tracker
}

// New returns an API server and starts tracking scan progress.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Go == nil {
		d.Go = func(fn func(context.Context)) { go fn(context.Background()) }
	}
	s := &Server{d: d}
	if d.Bus != nil {
		s.tracker = newTracker(d.Bus, d.Go)
	}
	return s
}

// Register mounts the API on the /scout group.
func (s *Server) Register(g *gin.RouterGroup) {
	api := g.Group("/api")
	api.POST("/auth/login", s.d.Auth.Login)

	a := api.Group("", s.d.Auth.Middleware())
	a.GET("/me", s.me)
	if s.d.Store == nil || s.d.Engine == nil {
		return // auth-only mode (tests)
	}
	a.GET("/overview", s.overview)
	a.GET("/scans", s.listScans)
	a.GET("/scans/running", s.runningScans)
	a.GET("/scans/:id", s.getScan)
	a.POST("/scans", s.startScan)
	a.GET("/findings", s.listFindings)
	a.GET("/findings/:fingerprint", s.getFinding)
	a.POST("/findings/status", s.setStatus)
	a.POST("/findings/:fingerprint/verify", s.verify)
	a.GET("/status", s.status)
	a.POST("/kill", s.kill)
	a.POST("/resume", s.resume)
	a.GET("/settings", s.settings)
	a.GET("/schedules", s.schedules)
	a.GET("/export", s.export)

	g.GET("/ws/live", s.d.Auth.Middleware(), s.live)
}

func (s *Server) me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"username": c.GetString(ctxUserKey)})
}

func fail(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}
