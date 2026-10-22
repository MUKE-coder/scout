package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Auth defaults.
const (
	TokenTTL       = 12 * time.Hour
	maxFailures    = 5
	failureWindow  = 15 * time.Minute
	tokenIssuer    = "scout"
	ctxUserKey     = "scout.user"
	bearerPrefix   = "Bearer "
	tokenQueryName = "token" // WebSocket clients cannot set headers
)

// Auth issues and verifies dashboard JWTs (HS256) and rate-limits logins.
type Auth struct {
	secret   []byte
	username string
	password string
	now      func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time // client IP -> recent failed attempts
}

// NewAuth returns an authenticator for one username/password.
func NewAuth(secret []byte, username, password string) *Auth {
	return &Auth{secret: secret, username: username, password: password, now: time.Now, failures: map[string][]time.Time{}}
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login checks credentials and returns a token. Failed attempts are counted
// per client IP; after maxFailures in failureWindow, logins return 429.
func (a *Auth) Login(c *gin.Context) {
	ip := c.ClientIP()
	if wait := a.lockedFor(ip); wait > 0 {
		c.Header("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed logins; try again later"})
		return
	}
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}
	// Compare both fields in constant time, and always both, so timing does
	// not reveal which one was wrong.
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(a.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(a.password)) == 1
	if !userOK || !passOK {
		a.recordFailure(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	a.clearFailures(ip)

	exp := a.now().Add(TokenTTL)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    tokenIssuer,
		Subject:   req.Username,
		IssuedAt:  jwt.NewNumericDate(a.now()),
		ExpiresAt: jwt.NewNumericDate(exp),
	}).SignedString(a.secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
		return
	}
	c.JSON(http.StatusOK, loginResponse{Token: token, ExpiresAt: exp})
}

// Verify parses and validates a token, returning its subject.
func (a *Auth) Verify(raw string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return a.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// Middleware rejects requests without a valid token. It reads the
// Authorization: Bearer header, or ?token= for WebSocket upgrades.
func (a *Auth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), bearerPrefix)
		if raw == "" || raw == c.GetHeader("Authorization") {
			raw = c.Query(tokenQueryName)
		}
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		user, err := a.Verify(raw)
		if err != nil {
			msg := "invalid token"
			if errors.Is(err, jwt.ErrTokenExpired) {
				msg = "session expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}
		c.Set(ctxUserKey, user)
		c.Next()
	}
}

func (a *Auth) lockedFor(ip string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	recent := a.prune(ip)
	if len(recent) < maxFailures {
		return 0
	}
	return recent[0].Add(failureWindow).Sub(a.now())
}

func (a *Auth) recordFailure(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.prune(ip), a.now())
}

func (a *Auth) clearFailures(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failures, ip)
}

// prune drops failures older than the window. Caller holds a.mu.
func (a *Auth) prune(ip string) []time.Time {
	cutoff := a.now().Add(-failureWindow)
	kept := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(a.failures, ip)
		return nil
	}
	a.failures[ip] = kept
	return kept
}
