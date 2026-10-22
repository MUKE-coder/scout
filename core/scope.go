package core

import (
	"net/url"
	"strings"
)

// Scope is the allowlist of what a scan may touch. Scout never widens it
// implicitly: the engine fills an empty Hosts list with the target's own host.
type Scope struct {
	// Hosts are exact hostnames ("api.example.com") or wildcard subdomains
	// ("*.example.com", which does not match the apex "example.com").
	Hosts []string `json:"hosts,omitempty" yaml:"hosts"`
	// IncludePaths are path prefixes; empty means every path on allowed hosts.
	IncludePaths []string `json:"include_paths,omitempty" yaml:"include_paths"`
	// ExcludePaths are path prefixes that are never touched. They win over includes.
	ExcludePaths []string `json:"exclude_paths,omitempty" yaml:"exclude_paths"`
}

// AllowsHost reports whether host (without port) is in scope.
func (s Scope) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, p := range s.Hosts {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// AllowsPath reports whether a URL path is in scope.
func (s Scope) AllowsPath(path string) bool {
	if path == "" {
		path = "/"
	}
	for _, p := range s.ExcludePaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	if len(s.IncludePaths) == 0 {
		return true
	}
	for _, p := range s.IncludePaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Allows reports whether a URL is in scope (host and path).
func (s Scope) Allows(u *url.URL) bool {
	return u != nil && s.AllowsHost(u.Hostname()) && s.AllowsPath(u.EscapedPath())
}
