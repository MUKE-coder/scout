// Package recon performs passive reconnaissance on a target's domain — the first
// step of a pen test: WHOIS registration data, DNS records, and subdomains from
// certificate transparency (crt.sh). It queries public services (WHOIS servers,
// resolvers, crt.sh), never the target directly beyond ordinary DNS, so it is
// safe in any mode. Everything is best-effort and timeout-bounded: a failed
// lookup is simply omitted.
package recon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MUKE-coder/scout/core"
)

// Gather runs WHOIS, DNS and subdomain discovery for a domain and returns what it
// found. ctx bounds the whole thing; nil is returned only when domain is unusable.
func Gather(ctx context.Context, domain string) *core.Recon {
	domain = registrable(domain)
	if domain == "" {
		return nil
	}
	r := &core.Recon{Domain: domain}
	// Run the three independent lookups concurrently so a slow one (crt.sh) does
	// not starve the others of the shared time budget.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); r.DNS = lookupDNS(ctx, domain) }()
	go func() { defer wg.Done(); r.WHOIS = whois(ctx, domain) }()
	go func() { defer wg.Done(); r.Subdomains = subdomains(ctx, domain) }()
	wg.Wait()
	if r.DNS == nil && r.WHOIS == nil && len(r.Subdomains) == 0 {
		return nil
	}
	return r
}

// registrable returns the domain to recon, or "" for an IP, localhost, or a bare
// host with no dot (nothing public to look up).
func registrable(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" || host == "localhost" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	return host
}

// --- DNS --------------------------------------------------------------------

func lookupDNS(ctx context.Context, domain string) *core.DNS {
	res := &net.Resolver{}
	d := &core.DNS{}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	if ips, err := res.LookupIPAddr(c, domain); err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				d.A = append(d.A, ip.IP.String())
			} else {
				d.AAAA = append(d.AAAA, ip.IP.String())
			}
		}
	}
	if mx, err := res.LookupMX(c, domain); err == nil {
		for _, m := range mx {
			d.MX = append(d.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := res.LookupNS(c, domain); err == nil {
		for _, n := range ns {
			d.NS = append(d.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := res.LookupTXT(c, domain); err == nil {
		d.TXT = txt
	}
	if cname, err := res.LookupCNAME(c, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != domain {
			d.CNAME = cname
		}
	}
	if len(d.A) > 0 {
		if names, err := res.LookupAddr(c, d.A[0]); err == nil {
			for _, n := range names {
				d.PTR = append(d.PTR, strings.TrimSuffix(n, "."))
			}
		}
	}
	sortAll(&d.A, &d.AAAA, &d.MX, &d.NS, &d.TXT, &d.PTR)
	if len(d.A)+len(d.AAAA)+len(d.MX)+len(d.NS)+len(d.TXT)+len(d.PTR) == 0 && d.CNAME == "" {
		return nil
	}
	return d
}

func sortAll(slices ...*[]string) {
	for _, s := range slices {
		sort.Strings(*s)
	}
}

// --- WHOIS ------------------------------------------------------------------

var (
	reWhoisServer = regexp.MustCompile(`(?i)^\s*(?:whois|refer):\s*(\S+)`)
	reEmail       = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

func whois(ctx context.Context, domain string) *core.WHOIS {
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	// 1. Ask IANA which WHOIS server is authoritative for the TLD.
	server := "whois.verisign-grs.com"
	if s := parseRefer(query(ctx, "whois.iana.org", tld)); s != "" {
		server = s
	}
	raw := query(ctx, server, domain)
	if raw == "" {
		return nil
	}
	// 2. Thin registries refer to the registrar's WHOIS for richer data.
	if ref := parseRefer(raw); ref != "" && ref != server {
		if more := query(ctx, ref, domain); more != "" {
			raw += "\n" + more
		}
	}
	return parseWhois(raw)
}

// query opens a WHOIS (port 43) connection, sends the query, and returns the
// response text. Best-effort: "" on any error.
func query(ctx context.Context, server, q string) string {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(c, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if dl, ok := c.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte(q + "\r\n")); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(conn, 1<<20))
	return string(b)
}

func parseRefer(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		if m := reWhoisServer.FindStringSubmatch(line); m != nil {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

func parseWhois(raw string) *core.WHOIS {
	w := &core.WHOIS{}
	nsSeen, stSeen, emSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(key))
		v := strings.TrimSpace(val)
		if v == "" {
			continue
		}
		switch {
		case w.Registrar == "" && k == "registrar":
			w.Registrar = v
		case w.Org == "" && (k == "registrant organization" || k == "registrant org" || k == "org" || k == "organization"):
			w.Org = v
		case w.Created == "" && (k == "creation date" || k == "created on" || k == "created" || k == "registered on" || k == "registration time"):
			w.Created = v
		case w.Expires == "" && (k == "registry expiry date" || k == "registrar registration expiration date" || k == "expiry date" || k == "expiration date" || k == "expires on" || k == "expire"):
			w.Expires = v
		case k == "name server" || k == "nserver":
			if ns := strings.ToLower(strings.Fields(v)[0]); !nsSeen[ns] {
				nsSeen[ns] = true
				w.NameServers = append(w.NameServers, ns)
			}
		case k == "domain status" || k == "status":
			st := strings.Fields(v)[0]
			if !stSeen[st] {
				stSeen[st] = true
				w.Status = append(w.Status, st)
			}
		}
		for _, em := range reEmail.FindAllString(v, -1) {
			em = strings.ToLower(em)
			if !emSeen[em] && !strings.Contains(em, "abuse") {
				emSeen[em] = true
				w.Emails = append(w.Emails, em)
			}
		}
	}
	sort.Strings(w.NameServers)
	sort.Strings(w.Status)
	if w.Registrar == "" && w.Created == "" && len(w.NameServers) == 0 {
		return nil
	}
	return w
}

// --- subdomains (certificate transparency via crt.sh) -----------------------

const maxSubdomains = 200

func subdomains(ctx context.Context, domain string) []string {
	c, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Scout/1 (+https://github.com/MUKE-coder/scout)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name == "" || name == domain || !strings.HasSuffix(name, "."+domain) || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) > maxSubdomains {
		out = out[:maxSubdomains]
	}
	return out
}
