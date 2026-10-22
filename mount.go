package scout

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

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
	return &Scout{
		cfg:       c,
		log:       log.With("app", c.AppName),
		store:     store,
		lifecycle: NewLifecycle(context.Background()),
	}, nil
}

// Register adds the /scout route group to r.
func (s *Scout) Register(r gin.IRouter) {
	g := r.Group(BasePath)
	api := g.Group("/api")
	api.GET("/health", s.handleHealth)

	g.GET("/ui/*path", func(c *gin.Context) {
		c.String(http.StatusOK, "Scout dashboard arrives in phase 5.")
	})
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
