package selftest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	key = []byte("0123456789abcdef0123456789abcdef")
	now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
)

// signedIncoming signs an outgoing request and returns it as the server
// would see it.
func signedIncoming(t *testing.T, method, url string) *http.Request {
	t.Helper()
	out := httptest.NewRequest(method, url, nil)
	Sign(out, key, "scan123", now)
	in := httptest.NewRequest(method, url, nil)
	in.Header.Set(Header, out.Header.Get(Header))
	return in
}

func TestSignVerifyRoundTrip(t *testing.T) {
	r := signedIncoming(t, http.MethodGet, "http://app.local:8080/api/users?id=1")
	info, err := Verify(r, key, now.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.ScanID != "scan123" || !info.Time.Equal(now) {
		t.Fatalf("info = %+v", info)
	}
}

func TestVerifyRejects(t *testing.T) {
	good := signedIncoming(t, http.MethodGet, "http://app.local/a")

	cases := []struct {
		name string
		req  func() *http.Request
		key  []byte
		at   time.Time
		want error
	}{
		{"missing", func() *http.Request { return httptest.NewRequest("GET", "http://app.local/a", nil) }, key, now, ErrMissing},
		{"malformed", func() *http.Request {
			r := httptest.NewRequest("GET", "http://app.local/a", nil)
			r.Header.Set(Header, "v1;garbage")
			return r
		}, key, now, ErrMalformed},
		{"wrong key", func() *http.Request { return good }, []byte("another-key"), now, ErrSignature},
		{"expired", func() *http.Request { return good }, key, now.Add(time.Hour), ErrExpired},
		{"future", func() *http.Request { return good }, key, now.Add(-time.Hour), ErrExpired},
		{"replayed on other path", func() *http.Request {
			r := httptest.NewRequest("GET", "http://app.local/b", nil)
			r.Header.Set(Header, good.Header.Get(Header))
			return r
		}, key, now, ErrSignature},
		{"replayed with other method", func() *http.Request {
			r := httptest.NewRequest("DELETE", "http://app.local/a", nil)
			r.Header.Set(Header, good.Header.Get(Header))
			return r
		}, key, now, ErrSignature},
		{"tampered scan id", func() *http.Request {
			r := httptest.NewRequest("GET", "http://app.local/a", nil)
			r.Header.Set(Header, strings.Replace(good.Header.Get(Header), "scan=scan123", "scan=other", 1))
			return r
		}, key, now, ErrSignature},
	}
	for _, c := range cases {
		if _, err := Verify(c.req(), c.key, c.at, 0); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestTransportSignsWithoutMutating(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r }))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{Key: key, ScanID: "s1", Now: func() time.Time { return now }}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req.Header.Get(Header) != "" {
		t.Fatal("caller's request was mutated")
	}
	if _, err := Verify(got, key, now, 0); err != nil {
		t.Fatalf("server could not verify: %v", err)
	}
}
