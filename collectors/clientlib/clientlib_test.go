package clientlib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/intel"
)

func TestParseLib(t *testing.T) {
	cases := []struct {
		url, name, ver string
		ok             bool
	}{
		{"/js/jquery-3.4.1.min.js", "jquery", "3.4.1", true},
		{"https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js", "bootstrap", "4.3.1", true},
		{"https://unpkg.com/vue@2.6.10/dist/vue.js", "vue", "2.6.10", true},
		{"https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js", "jquery", "1.12.4", true},
		{"https://ajax.googleapis.com/ajax/libs/angularjs/1.7.8/angular.min.js", "angular", "1.7.8", true},
		{"/wp-includes/js/jquery/jquery.min.js?ver=3.6.0", "jquery", "3.6.0", true},
		{"/static/lodash.min.js?v=4.17.11", "lodash", "4.17.11", true},
		// Negatives: no version, or not a known library.
		{"/js/app-1.2.3.min.js", "", "", false},
		{"/css/bootstrap.min.css", "", "", false},
		{"https://example.com/main.js", "", "", false},
	}
	for _, c := range cases {
		name, ver, ok := parseLib(c.url)
		if ok != c.ok || name != c.name || ver != c.ver {
			t.Errorf("parseLib(%q) = (%q,%q,%v), want (%q,%q,%v)", c.url, name, ver, ok, c.name, c.ver, c.ok)
		}
	}
}

type fakeDB struct{}

func (fakeDB) Source() string { return "fake" }
func (fakeDB) Query(_ context.Context, pkgs []intel.Package) ([][]intel.Vuln, error) {
	out := make([][]intel.Vuln, len(pkgs))
	for i, p := range pkgs {
		if p.Name == "jquery" && p.Version == "3.4.1" {
			out[i] = []intel.Vuln{{
				ID: "GHSA-gxr4-xjj5-5px2", Aliases: []string{"CVE-2020-11022"},
				Summary: "XSS in jQuery.htmlPrefilter", Severity: "Medium", Fixed: "3.5.0",
			}}
		}
	}
	return out, nil
}

func scanCtx(srv *httptest.Server) context.Context {
	return core.WithScanCache(core.WithHTTPClient(context.Background(), srv.Client()))
}

func TestRunDetectsVulnerableLib(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<html><head>
				<script src="/js/jquery-3.4.1.min.js"></script>
				<script src="/js/app-9.9.9.min.js"></script>
				<link rel="stylesheet" href="/css/bootstrap.min.css">
			</head></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origDB, origEn := db, enrich
	db = fakeDB{}
	enrich = func(_ context.Context, vulns []*intel.Vuln) {
		for _, v := range vulns {
			if v.CVEID() == "CVE-2020-11022" {
				v.CVE, v.EPSS, v.EPSSPctl = "CVE-2020-11022", 0.42, 0.9
			}
		}
	}
	defer func() { db, enrich = origDB, origEn }()

	got, err := Scan{}.Run(scanCtx(srv), core.Target{URL: srv.URL, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding (jquery only), got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Value != "jquery@3.4.1" {
		t.Errorf("asset = %q", f.Asset.Value)
	}
	if !strings.Contains(f.Title, "Outdated client-side library jquery@3.4.1") {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.Evidence.Notes, "jquery-3.4.1.min.js") || !strings.Contains(f.Evidence.Notes, "EPSS 42%") {
		t.Errorf("notes missing source/EPSS: %q", f.Evidence.Notes)
	}
	if !strings.Contains(f.Remediation.How[0].Code, "3.5.0") {
		t.Errorf("remediation missing fixed version: %q", f.Remediation.How[0].Code)
	}
}

func TestNoURL(t *testing.T) {
	got, err := Scan{}.Run(core.WithScanCache(context.Background()), core.Target{Repo: ".", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("url-less should be a no-op: %v %v", got, err)
	}
}
