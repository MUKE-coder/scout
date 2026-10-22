package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func testServer(t *testing.T) (*gin.Engine, *Auth) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	auth := NewAuth([]byte("test-secret-0123456789abcdef"), "ops", "correct horse")
	r := gin.New()
	New(Deps{Auth: auth}).Register(r.Group("/scout"))
	return r, auth
}

func do(r *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "203.0.113.7:5000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func login(t *testing.T, r *gin.Engine, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	return do(r, http.MethodPost, "/scout/api/auth/login", string(b), "")
}

func TestLoginAndProtectedRoute(t *testing.T) {
	r, _ := testServer(t)
	if w := do(r, http.MethodGet, "/scout/api/me", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	w := login(t, r, "ops", "correct horse")
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var resp loginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token == "" || time.Until(resp.ExpiresAt) < 11*time.Hour {
		t.Fatalf("bad token response: %+v", resp)
	}
	w = do(r, http.MethodGet, "/scout/api/me", "", resp.Token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"ops"`) {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	// Query-string token (used by the WebSocket).
	if w := do(r, http.MethodGet, "/scout/api/me?token="+resp.Token, "", ""); w.Code != http.StatusOK {
		t.Fatalf("query token: %d", w.Code)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	r, _ := testServer(t)
	for _, c := range [][2]string{{"ops", "wrong"}, {"root", "correct horse"}, {"", ""}} {
		if w := login(t, r, c[0], c[1]); w.Code == http.StatusOK {
			t.Errorf("%q/%q logged in", c[0], c[1])
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	r, auth := testServer(t)
	clock := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	auth.now = func() time.Time { return clock }

	for i := range maxFailures {
		if w := login(t, r, "ops", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	// Locked out, even with the right password.
	w := login(t, r, "ops", "correct horse")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d", w.Code)
	}
	// After the window, the right password works and clears the counter.
	clock = clock.Add(failureWindow + time.Second)
	if w := login(t, r, "ops", "correct horse"); w.Code != http.StatusOK {
		t.Fatalf("after window: %d", w.Code)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	_, auth := testServer(t)
	sign := func(secret string, claims jwt.RegisteredClaims) string {
		s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		return s
	}
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	cases := map[string]string{
		"wrong secret": sign("other-secret", jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: future}),
		"expired":      sign("test-secret-0123456789abcdef", jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute))}),
		"no expiry":    sign("test-secret-0123456789abcdef", jwt.RegisteredClaims{Issuer: tokenIssuer}),
		"wrong issuer": sign("test-secret-0123456789abcdef", jwt.RegisteredClaims{Issuer: "evil", ExpiresAt: future}),
		"garbage":      "not.a.jwt",
	}
	for name, tok := range cases {
		if _, err := auth.Verify(tok); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	// HS384 is a different method: only HS256 is accepted.
	hs384, _ := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.RegisteredClaims{Issuer: tokenIssuer, ExpiresAt: future}).
		SignedString([]byte("test-secret-0123456789abcdef"))
	if _, err := auth.Verify(hs384); err == nil {
		t.Error("non-HS256 token accepted")
	}
}
