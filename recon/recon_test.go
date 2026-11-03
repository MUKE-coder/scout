package recon

import "testing"

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"tesla.com":   "tesla.com",
		"TESLA.COM.":  "tesla.com",
		"sub.a.co.uk": "sub.a.co.uk",
		"127.0.0.1":   "",
		"::1":         "",
		"localhost":   "",
		"nodot":       "",
		"":            "",
	}
	for in, want := range cases {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRefer(t *testing.T) {
	raw := "% IANA WHOIS server\ndomain:       COM\nwhois:        whois.verisign-grs.com\n"
	if got := parseRefer(raw); got != "whois.verisign-grs.com" {
		t.Errorf("parseRefer = %q", got)
	}
	if got := parseRefer("no referral here"); got != "" {
		t.Errorf("parseRefer should be empty, got %q", got)
	}
}

func TestParseWhois(t *testing.T) {
	raw := `Domain Name: TESLA.COM
Registrar: MarkMonitor Inc.
Registrant Organization: Tesla, Inc.
Creation Date: 1992-11-04T05:00:00Z
Registry Expiry Date: 2028-11-03T05:00:00Z
Name Server: A1-12.AKAM.NET
Name Server: A7-66.AKAM.NET
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Email: admin@tesla.com
Registrar Abuse Contact Email: abuse@markmonitor.com
`
	w := parseWhois(raw)
	if w == nil {
		t.Fatal("parseWhois returned nil")
	}
	if w.Registrar != "MarkMonitor Inc." {
		t.Errorf("registrar = %q", w.Registrar)
	}
	if w.Org != "Tesla, Inc." {
		t.Errorf("org = %q", w.Org)
	}
	if w.Created == "" || w.Expires == "" {
		t.Errorf("dates missing: created=%q expires=%q", w.Created, w.Expires)
	}
	if len(w.NameServers) != 2 {
		t.Errorf("name servers = %v", w.NameServers)
	}
	if len(w.Status) != 1 || w.Status[0] != "clientTransferProhibited" {
		t.Errorf("status = %v", w.Status)
	}
	// admin@ kept, abuse@ dropped.
	hasAdmin, hasAbuse := false, false
	for _, e := range w.Emails {
		if e == "admin@tesla.com" {
			hasAdmin = true
		}
		if e == "abuse@markmonitor.com" {
			hasAbuse = true
		}
	}
	if !hasAdmin || hasAbuse {
		t.Errorf("emails = %v (want admin, not abuse)", w.Emails)
	}
}
