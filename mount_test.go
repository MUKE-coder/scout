package scout

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/core"
)

func TestMountRegistersScoutGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := Mount(r, Config{AppName: "My API"})
	defer s.Close(time.Second)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/scout/api/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("health status = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["app"] != "My API" || body["version"] != Version || body["mode"] != "safe" {
		t.Fatalf("health body = %v", body)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/scout/ui/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ui status = %d", w.Code)
	}
}

func TestMountedLoginFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := Mount(r, Config{AppName: "x", Username: "ops", Password: "long-random-password"})
	defer s.Close(time.Second)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/scout/api/me", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me = %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/scout/api/auth/login",
		strings.NewReader(`{"username":"ops","password":"long-random-password"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("login = %d %s", w.Code, w.Body)
	}
}

func TestMountedSchedules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := Mount(r, Config{
		AppName:   "x",
		Targets:   []core.Target{{Name: "shop", URL: "http://localhost:1"}},
		Schedules: []Schedule{{Name: "nightly", Cron: "0 3 * * *", Targets: []string{"shop"}}},
	})
	defer s.Close(time.Second)
	if s.scheduler == nil {
		t.Fatal("scheduler not started")
	}
	info := s.scheduler.info(s.cfg.Schedules)
	if len(info) != 1 || info[0].Next.IsZero() || info[0].Next.Hour() != 3 {
		t.Fatalf("info = %+v", info)
	}
	if _, err := New(Config{Schedules: []Schedule{{Name: "x", Cron: "@daily"}}}); err == nil {
		t.Fatal("schedules without targets must be rejected")
	}
}

func TestMountResolvesRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// WithRoutes: an explicit middleware-aware table is attached to the
	// target that has none, and exposed at /scout/api/routes.
	r := gin.New()
	routes := []core.Route{
		{Method: "GET", Path: "/admin/users", Middleware: []string{"Logger"}},
		{Method: "GET", Path: "/admin/stats", Middleware: []string{"Logger", "JWTAuth"}},
	}
	s := Mount(r, Config{
		AppName: "x",
		Targets: []core.Target{{Name: "app", URL: "http://localhost:8080", Environment: core.EnvDev}},
	}, WithRoutes(routes...))
	defer s.Close(time.Second)

	if len(s.Routes()) != 2 || len(s.cfg.Targets[0].Routes) != 2 {
		t.Fatalf("WithRoutes not attached: scout=%d target=%d", len(s.Routes()), len(s.cfg.Targets[0].Routes))
	}
	if s.cfg.Targets[0].Routes[0].Middleware[0] != "Logger" {
		t.Fatal("middleware chain lost")
	}

	// gin introspection fallback: with no WithRoutes, the engine's own routes
	// are recovered (method/path), skipping Scout's /scout/* routes.
	r2 := gin.New()
	r2.GET("/api/todos", func(c *gin.Context) {})
	r2.POST("/api/todos", func(c *gin.Context) {})
	s2 := Mount(r2, Config{AppName: "y", Targets: []core.Target{{Name: "app", URL: "http://localhost:9", Environment: core.EnvDev}}})
	defer s2.Close(time.Second)
	got := map[string]bool{}
	for _, rt := range s2.Routes() {
		got[rt.Method+" "+rt.Path] = true
		if strings.HasPrefix(rt.Path, "/scout") {
			t.Errorf("introspection leaked a Scout route: %s", rt.Path)
		}
	}
	if !got["GET /api/todos"] || !got["POST /api/todos"] {
		t.Fatalf("gin introspection missed routes: %v", got)
	}
}

func TestMountKeepsDefaultsForPartialConfig(t *testing.T) {
	s, err := New(Config{AppName: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(time.Second)
	c := s.Config()
	if c.Environment != core.EnvDev || c.RateLimit != DefaultRateLimit || c.Mode != core.ModeSafe {
		t.Fatalf("defaults lost: %+v", c)
	}
}

func TestMountPanicsOnUnsafeConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for default creds in prod")
		}
	}()
	Mount(gin.New(), Config{Environment: core.EnvProd})
}
