package scout

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/api"
	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/engine"
	"github.com/MUKE-coder/scout/scoring"
	"github.com/MUKE-coder/scout/selftest"
	"github.com/MUKE-coder/scout/storage"
)

// URL namespace shared with Sentinel and Pulse.
const (
	BasePath = "/scout"
	APIPath  = BasePath + "/api"
	UIPath   = BasePath + "/ui"
	WSPath   = BasePath + "/ws/live"
)

// Scout is a mounted Scout instance.
type Scout struct {
	cfg       Config
	log       *slog.Logger
	store     storage.Store
	auth      *api.Auth
	engine    *engine.Engine
	bus       *engine.Bus
	kill      *engine.KillSwitch
	scheduler *scheduler
	lifecycle *Lifecycle
}

// Mount attaches Scout to a Gin router under /scout and returns the
// instance. It is the one-line integration:
//
//	scout.Mount(router, scout.Config{AppName: "My API"})
//
// Mount panics on invalid configuration, matching Sentinel and Pulse; use
// New + Register when you want the error instead.
func Mount(r gin.IRouter, cfg Config, opts ...Option) *Scout {
	s, err := New(cfg, opts...)
	if err != nil {
		panic(fmt.Sprintf("scout: %v", err))
	}
	s.Register(r)
	return s
}

// New builds a Scout instance without mounting it.
func New(cfg Config, opts ...Option) (*Scout, error) {
	base := DefaultConfig()
	mergeConfig(&base, cfg)
	c, err := NewConfig(append([]Option{WithConfig(base)}, opts...)...)
	if err != nil {
		return nil, err
	}
	if err := c.ValidateDashboard(); err != nil {
		return nil, err
	}

	var store storage.Store = storage.NewMemory(storage.DefaultMemoryCapacity)
	if c.DBPath != "" {
		if store, err = storage.OpenSQLite(c.DBPath); err != nil {
			return nil, err
		}
	}
	log, _ := NewLogger(os.Stderr, "info", "text")
	log = log.With("app", c.AppName)

	secret := []byte(c.JWTSecret)
	if len(secret) == 0 {
		secret = selftest.NewKey()
		log.Warn("no jwt_secret configured: using a random one, so dashboard sessions end when Scout restarts")
	}
	window, err := c.Window.EngineWindow()
	if err != nil {
		return nil, err
	}
	bus, kill := engine.NewBus(), engine.NewKillSwitch()
	eng := engine.New(core.DefaultRegistry, engine.Options{
		Concurrency:  c.Concurrency,
		CheckTimeout: c.CheckTimeout,
		RateLimit:    c.RateLimit,
		Scope:        c.Scope,
		Window:       window,
		Kill:         kill,
		SigningKey:   []byte(c.SigningKey),
		Store:        store,
		Bus:          bus,
		Scoring:      scoring.Options{Criticality: c.Criticality},
		Logger:       log,
	})
	s := &Scout{
		cfg:       c,
		log:       log,
		store:     store,
		auth:      api.NewAuth(secret, c.Username, c.Password),
		engine:    eng,
		bus:       bus,
		kill:      kill,
		lifecycle: NewLifecycle(context.Background()),
	}
	s.lifecycle.Go(func(ctx context.Context) {
		runPruner(ctx, store, c.Retention, DefaultPruneInterval, log)
	})
	if len(c.Schedules) > 0 {
		sched, start, err := newScheduler(c.Schedules, c.Targets, log, s.runScheduled)
		if err != nil {
			_ = s.lifecycle.Shutdown(time.Second)
			return nil, err
		}
		s.scheduler = sched
		s.lifecycle.Go(start)
		log.Info("schedules active", "count", len(c.Schedules))
	}
	return s, nil
}

// Register adds the /scout route group to r.
func (s *Scout) Register(r gin.IRouter) {
	g := r.Group(BasePath)
	g.GET("/api/health", s.handleHealth)
	api.New(api.Deps{
		Auth:     s.auth,
		Store:    s.store,
		Engine:   s.engine,
		Bus:      s.bus,
		Kill:     s.kill,
		Settings: s.settings(),
		Scoring:  scoring.Options{Criticality: s.cfg.Criticality},
		Go:       s.lifecycle.Go,
		Logger:   s.log,
		Schedules: func() any {
			return s.scheduler.info(s.cfg.Schedules)
		},
	}).Register(g)

	registerDashboard(g)
	s.log.Info("scout mounted", "base", BasePath, "env", s.cfg.Environment, "mode", s.cfg.EffectiveMode())
}

func (s *Scout) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":      "ok",
		"version":     Version,
		"app":         s.cfg.AppName,
		"environment": s.cfg.Environment,
		"mode":        s.cfg.EffectiveMode(),
	})
}

// settings is the secret-free view of the config for the dashboard.
func (s *Scout) settings() api.Settings {
	var window any
	if s.cfg.Window != nil {
		window = s.cfg.Window
	}
	return api.Settings{
		AppName: s.cfg.AppName, Environment: s.cfg.Environment, Mode: s.cfg.Mode,
		Targets: s.cfg.Targets, Scope: s.cfg.Scope, Criticality: s.cfg.Criticality,
		RateLimit: s.cfg.RateLimit, Concurrency: s.cfg.Concurrency,
		CheckTimeout: s.cfg.CheckTimeout, Retention: s.cfg.Retention,
		Window: window, Version: Version,
	}
}

// Config returns the effective configuration.
func (s *Scout) Config() Config { return s.cfg }

// Store returns the backing store.
func (s *Scout) Store() storage.Store { return s.store }

// Close stops background work and closes storage.
func (s *Scout) Close(timeout time.Duration) error {
	err := s.lifecycle.Shutdown(timeout)
	if cerr := s.store.Close(); err == nil {
		err = cerr
	}
	return err
}

// mergeConfig copies the non-zero fields of src onto dst, so callers can
// pass a partial Config literal and keep the defaults for the rest.
func mergeConfig(dst *Config, src Config) {
	if src.AppName != "" {
		dst.AppName = src.AppName
	}
	if src.Environment != "" {
		dst.Environment = src.Environment
	}
	if src.Mode != 0 {
		dst.Mode = src.Mode
	}
	if len(src.Targets) > 0 {
		dst.Targets = src.Targets
	}
	if len(src.Scope.Hosts)+len(src.Scope.IncludePaths)+len(src.Scope.ExcludePaths) > 0 {
		dst.Scope = src.Scope
	}
	if len(src.Schedules) > 0 {
		dst.Schedules = src.Schedules
	}
	if src.Window != nil {
		dst.Window = src.Window
	}
	if len(src.Criticality) > 0 {
		dst.Criticality = src.Criticality
	}
	if src.RateLimit != 0 {
		dst.RateLimit = src.RateLimit
	}
	if src.Concurrency != 0 {
		dst.Concurrency = src.Concurrency
	}
	if src.CheckTimeout != 0 {
		dst.CheckTimeout = src.CheckTimeout
	}
	if src.DBPath != "" {
		dst.DBPath = src.DBPath
	}
	if src.Retention != 0 {
		dst.Retention = src.Retention
	}
	if src.SigningKey != "" {
		dst.SigningKey = src.SigningKey
	}
	if src.Username != "" {
		dst.Username = src.Username
	}
	if src.Password != "" {
		dst.Password = src.Password
	}
	if src.JWTSecret != "" {
		dst.JWTSecret = src.JWTSecret
	}
}
