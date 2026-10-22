package scout

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
