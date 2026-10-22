package core

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestScopeHosts(t *testing.T) {
	s := Scope{Hosts: []string{"example.com", "*.api.example.com", "Shop.Example.org."}}
	cases := map[string]bool{
		"example.com":         true,
		"EXAMPLE.com":         true,
		"example.com.":        true,
		"www.example.com":     false, // exact entries do not match subdomains
		"v1.api.example.com":  true,
		"api.example.com":     false, // wildcard excludes the apex
		"evilexample.com":     false,
		"example.com.evil.io": false,
		"shop.example.org":    true,
		"":                    false,
	}
	for host, want := range cases {
		if got := s.AllowsHost(host); got != want {
			t.Errorf("AllowsHost(%q) = %v, want %v", host, got, want)
		}
	}
	if (Scope{}).AllowsHost("example.com") {
		t.Error("empty scope must allow nothing")
	}
}

func TestScopePaths(t *testing.T) {
	s := Scope{IncludePaths: []string{"/api"}, ExcludePaths: []string{"/api/admin"}}
	cases := map[string]bool{
		"/api/users":       true,
		"/api/admin/users": false, // exclude wins over include
		"/other":           false,
		"":                 false,
	}
	for path, want := range cases {
		if got := s.AllowsPath(path); got != want {
			t.Errorf("AllowsPath(%q) = %v, want %v", path, got, want)
		}
	}
	if !(Scope{}).AllowsPath("/anything") {
		t.Error("no include list means every path is allowed")
	}
}

func TestScopeAllowsURL(t *testing.T) {
	s := Scope{Hosts: []string{"example.com"}, ExcludePaths: []string{"/logout"}}
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if !s.Allows(parse("https://example.com:8443/a?x=1")) {
		t.Error("in-scope URL rejected")
	}
	if s.Allows(parse("https://example.com/logout")) || s.Allows(parse("https://other.com/")) || s.Allows(nil) {
		t.Error("out-of-scope URL allowed")
	}
}

func TestHTTPClientRefusesOutsideScan(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/", nil)
	if _, err := HTTPClient(context.Background()).Do(req); !errors.Is(err, ErrNoGuardedClient) {
		t.Fatalf("err = %v, want ErrNoGuardedClient", err)
	}
}

func TestHTTPClientFromContext(t *testing.T) {
	custom := &http.Client{}
	ctx := WithHTTPClient(context.Background(), custom)
	if HTTPClient(ctx) != custom {
		t.Fatal("did not return the attached client")
	}
}
