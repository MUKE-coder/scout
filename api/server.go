package api

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Deps are what the API needs. The root package wires them in, so api never
// imports it.
type Deps struct {
	Auth   *Auth
	Logger *slog.Logger
}

// Server serves /scout/api/* and /scout/ws/live.
type Server struct {
	d Deps
}

// New returns an API server.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{d: d}
}

// Register mounts the API on the /scout group.
func (s *Server) Register(g *gin.RouterGroup) {
	api := g.Group("/api")
	api.POST("/auth/login", s.d.Auth.Login)

	authed := api.Group("", s.d.Auth.Middleware())
	authed.GET("/me", s.me)
}

func (s *Server) me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"username": c.GetString(ctxUserKey)})
}
