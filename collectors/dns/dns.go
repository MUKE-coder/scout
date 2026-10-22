// Package dns checks a target domain's DNS posture: email anti-spoofing
// records (SPF, DKIM, DMARC), certificate-issuance control (CAA), and
// dangling / takeover-prone CNAMEs. Every check is passive — it performs DNS
// lookups only, never HTTP, and sends no attack traffic. Lookups honor ctx and
// are memoized for the scan.
package dns

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(SPF{})
	core.Register(DMARC{})
	core.Register(DKIM{})
	core.Register(CAA{})
	core.Register(DanglingCNAME{})
	core.Register(SubdomainTakeover{})
}

// Resolver is the DNS surface the checks use. net.Resolver satisfies it; tests
// inject a fake. The engine does not provide one, so checks fall back to the
// system resolver via resolverFrom.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCAA(ctx context.Context, name string) ([]string, error)
}

type resolverKey struct{}

// WithResolver attaches a Resolver to ctx (used by tests).
func WithResolver(ctx context.Context, r Resolver) context.Context {
	return context.WithValue(ctx, resolverKey{}, r)
}

func resolverFrom(ctx context.Context) Resolver {
	if r, ok := ctx.Value(resolverKey{}).(Resolver); ok && r != nil {
		return r
	}
	return sysResolver{}
}

// sysResolver adapts net.DefaultResolver. CAA is not in net.Resolver, so it is
// approximated as unsupported and the CAA check treats "unsupported" as "no
// record found" only when it genuinely gets no answer.
type sysResolver struct{}

func (sysResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}
func (sysResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}
func (sysResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// LookupCAA uses a raw lookup where available; net.Resolver has no CAA method,
// so this returns errCAAUnsupported and the check degrades to informational.
func (sysResolver) LookupCAA(ctx context.Context, name string) ([]string, error) {
	return nil, errCAAUnsupported
}

var errCAAUnsupported = errors.New("dns: CAA lookup not supported by this resolver")

// domain returns the registrable host of the target, or "" if none.
func domain(t core.Target) string {
	if t.URL == "" {
		return ""
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if h == "" || net.ParseIP(h) != nil {
		return "" // DNS posture checks don't apply to a bare IP
	}
	return strings.TrimSuffix(h, ".")
}

func asset(t core.Target, dom string) core.Asset {
	exp := core.ExposureInternet
	if t.IsLocal() {
		exp = core.ExposureInternal
	}
	return core.Asset{Kind: core.AssetDomain, Value: dom, Host: dom, Exposure: exp, Criticality: t.Criticality}
}

// txt returns the TXT records for name, memoized per scan.
func txt(ctx context.Context, r Resolver, name string) ([]string, error) {
	return core.Memo(ctx, "dns.txt:"+name, func() ([]string, error) {
		return r.LookupTXT(ctx, name)
	})
}

// SPF flags a domain with no SPF record (or a dangerously permissive one).
type SPF struct{}

func (SPF) ID() string              { return "dns.spf" }
func (SPF) Category() core.Category { return core.CategoryDNS }
func (SPF) Mode() core.Mode         { return core.ModePassive }
func (SPF) Description() string     { return "Domain has no SPF record (email spoofing)" }
func (SPF) OWASP() []string         { return []string{"A05:2021"} }

func (SPF) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	records, err := txt(ctx, r, dom)
	if err != nil && !isNoHost(err) {
		return nil, err
	}
	var spf string
	for _, rec := range records {
		if strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
			spf = rec
			break
		}
	}
	if spf == "" {
		return []core.Finding{{
			Title:      "No SPF record",
			Category:   core.CategoryDNS,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, dom),
			Evidence:   core.Evidence{Notes: "no v=spf1 TXT record found for " + dom},
			CWE:        []string{"CWE-290"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:   "The domain publishes no SPF record.",
				Why:    "Without SPF, anyone can send email claiming to be from this domain, enabling phishing of your users and partners.",
				How:    txtFix(dom, "v=spf1 include:_spf.yourprovider.com -all"),
				Effort: core.EffortS,
				References: []string{
					"https://datatracker.ietf.org/doc/html/rfc7208",
				},
			},
		}}, nil
	}
	// A "+all" policy accepts mail from anywhere — worse than nothing.
	if strings.Contains(strings.ToLower(spf), "+all") {
		return []core.Finding{{
			Title:      "SPF record allows any sender (+all)",
			Category:   core.CategoryDNS,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, dom),
			Evidence:   core.Evidence{Matched: spf},
			CWE:        []string{"CWE-290"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:       "The SPF record ends in +all, which authorizes every sender.",
				Why:        "A +all policy defeats the purpose of SPF: any server may send as your domain and pass the check.",
				How:        txtFix(dom, "v=spf1 include:_spf.yourprovider.com -all"),
				Effort:     core.EffortS,
				References: []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
			},
		}}, nil
	}
	return nil, nil
}

// DMARC flags a missing or monitor-only DMARC policy.
type DMARC struct{}

func (DMARC) ID() string              { return "dns.dmarc" }
func (DMARC) Category() core.Category { return core.CategoryDNS }
func (DMARC) Mode() core.Mode         { return core.ModePassive }
func (DMARC) Description() string     { return "Domain has no enforcing DMARC policy" }
func (DMARC) OWASP() []string         { return []string{"A05:2021"} }

func (DMARC) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	records, err := txt(ctx, r, "_dmarc."+dom)
	if err != nil && !isNoHost(err) {
		return nil, err
	}
	var dmarc string
	for _, rec := range records {
		if strings.HasPrefix(strings.ToLower(rec), "v=dmarc1") {
			dmarc = rec
			break
		}
	}
	if dmarc == "" {
		return []core.Finding{{
			Title:      "No DMARC record",
			Category:   core.CategoryDNS,
			Severity:   core.SeverityMedium,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, dom),
			Evidence:   core.Evidence{Notes: "no v=DMARC1 TXT record at _dmarc." + dom},
			CWE:        []string{"CWE-290"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:       "The domain publishes no DMARC policy.",
				Why:        "DMARC tells receiving servers what to do with mail that fails SPF/DKIM. Without it, spoofed mail is more likely to be delivered.",
				How:        txtFix("_dmarc."+dom, "v=DMARC1; p=reject; rua=mailto:dmarc@"+dom),
				Effort:     core.EffortS,
				References: []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			},
		}}, nil
	}
	if policy := dmarcPolicy(dmarc); policy == "none" {
		return []core.Finding{{
			Title:      "DMARC policy is monitor-only (p=none)",
			Category:   core.CategoryDNS,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, dom),
			Evidence:   core.Evidence{Matched: dmarc},
			CWE:        []string{"CWE-290"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What:       "DMARC is set to p=none, which only reports failures and enforces nothing.",
				Why:        "With p=none, spoofed mail still reaches inboxes. Move to quarantine or reject once your reports look clean.",
				How:        txtFix("_dmarc."+dom, "v=DMARC1; p=reject; rua=mailto:dmarc@"+dom),
				Effort:     core.EffortS,
				References: []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			},
		}}, nil
	}
	return nil, nil
}

func dmarcPolicy(rec string) string {
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if v, ok := strings.CutPrefix(part, "p="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// DKIM checks a handful of common selectors and reports when none publish a
// key. DKIM selectors are app-specific, so a miss is "possible", not confirmed.
type DKIM struct{}

func (DKIM) ID() string              { return "dns.dkim" }
func (DKIM) Category() core.Category { return core.CategoryDNS }
func (DKIM) Mode() core.Mode         { return core.ModePassive }
func (DKIM) Description() string     { return "No DKIM key found on common selectors" }
func (DKIM) OWASP() []string         { return []string{"A05:2021"} }

// commonSelectors are the selectors major providers use, checked in order.
var commonSelectors = []string{"default", "google", "selector1", "selector2", "k1", "mail", "dkim"}

func (DKIM) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	for _, sel := range commonSelectors {
		records, err := txt(ctx, r, sel+"._domainkey."+dom)
		if err != nil && !isNoHost(err) {
			return nil, err
		}
		for _, rec := range records {
			if strings.Contains(strings.ToLower(rec), "v=dkim1") || strings.Contains(strings.ToLower(rec), "k=rsa") || strings.Contains(rec, "p=") {
				return nil, nil // a key exists on some common selector
			}
		}
	}
	return []core.Finding{{
		Title:      "No DKIM key found on common selectors",
		Category:   core.CategoryDNS,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidencePossible,
		Asset:      asset(t, dom),
		Evidence:   core.Evidence{Notes: "checked selectors: " + strings.Join(commonSelectors, ", ")},
		CWE:        []string{"CWE-290"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "No DKIM record was found on the common selectors Scout checks. If you use a custom selector this may be a false positive.",
			Why:  "DKIM signs outbound mail so receivers can verify it was not altered and really came from you. Without it, DMARC enforcement is weaker.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Enable DKIM signing with your email provider and publish the selector key it gives you as a TXT record."},
			},
			Effort:     core.EffortS,
			References: []string{"https://datatracker.ietf.org/doc/html/rfc6376"},
		},
	}}, nil
}

// CAA flags a domain with no CAA record (any CA may issue certs for it).
type CAA struct{}

func (CAA) ID() string              { return "dns.caa" }
func (CAA) Category() core.Category { return core.CategoryDNS }
func (CAA) Mode() core.Mode         { return core.ModePassive }
func (CAA) Description() string     { return "Domain has no CAA record" }
func (CAA) OWASP() []string         { return []string{"A05:2021"} }

func (CAA) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	records, err := core.Memo(ctx, "dns.caa:"+dom, func() ([]string, error) {
		return r.LookupCAA(ctx, dom)
	})
	if errors.Is(err, errCAAUnsupported) {
		return nil, nil // resolver can't do CAA; stay silent rather than guess
	}
	if err != nil && !isNoHost(err) {
		return nil, err
	}
	if len(records) > 0 {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "No CAA record",
		Category:   core.CategoryDNS,
		Severity:   core.SeverityLow,
		Confidence: core.ConfidenceConfirmed,
		Asset:      asset(t, dom),
		Evidence:   core.Evidence{Notes: "no CAA record found for " + dom},
		CWE:        []string{"CWE-295"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What:   "The domain publishes no CAA record, so any certificate authority may issue certificates for it.",
			Why:    "A CAA record restricts issuance to CAs you choose, reducing the risk of a mis-issued certificate being used to impersonate your site.",
			How:    txtFix(dom+" (CAA)", `0 issue "letsencrypt.org"`),
			Effort: core.EffortS,
			References: []string{
				"https://datatracker.ietf.org/doc/html/rfc8659",
			},
		},
	}}, nil
}

// takeoverFingerprints maps CNAME target suffixes to services known for
// dangling-record takeover when the backing resource is unclaimed.
var takeoverFingerprints = []string{
	".github.io", ".herokuapp.com", ".herokudns.com", ".s3.amazonaws.com",
	".cloudfront.net", ".azurewebsites.net", ".cloudapp.net", ".pages.dev",
	".netlify.app", ".ghost.io", ".surge.sh", ".fastly.net", ".readthedocs.io",
}

// DanglingCNAME flags a CNAME that points to a name which does not resolve to
// any address — a classic dangling record.
type DanglingCNAME struct{}

func (DanglingCNAME) ID() string              { return "dns.dangling-cname" }
func (DanglingCNAME) Category() core.Category { return core.CategoryDNS }
func (DanglingCNAME) Mode() core.Mode         { return core.ModePassive }
func (DanglingCNAME) Description() string     { return "CNAME points to a name that does not resolve" }
func (DanglingCNAME) OWASP() []string         { return []string{"A05:2021"} }

func (DanglingCNAME) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	cname, err := cnameOf(ctx, r, dom)
	if err != nil || cname == "" || strings.EqualFold(strings.TrimSuffix(cname, "."), dom) {
		return nil, err // no CNAME (host is an A record) or lookup failed
	}
	addrs, err := r.LookupHost(ctx, cname)
	if err == nil && len(addrs) > 0 {
		return nil, nil // target resolves: not dangling
	}
	if err != nil && !isNoHost(err) {
		return nil, err
	}
	return []core.Finding{{
		Title:      "Dangling CNAME to " + cname,
		Category:   core.CategoryDNS,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceLikely,
		Asset:      asset(t, dom),
		Evidence:   core.Evidence{Matched: dom + " CNAME " + cname + " (no address)"},
		CWE:        []string{"CWE-350"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: dom + " is a CNAME to " + cname + ", which does not resolve to any address.",
			Why:  "A CNAME to a decommissioned host can be claimed by an attacker if the underlying service lets anyone register that name, letting them serve content from your domain (subdomain takeover).",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Remove the dangling CNAME record, or re-point it to a resource you control."},
			},
			Effort:     core.EffortS,
			References: []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}}, nil
}

// SubdomainTakeover flags a CNAME to a takeover-prone provider whose backing
// resource appears unclaimed (target does not resolve).
type SubdomainTakeover struct{}

func (SubdomainTakeover) ID() string              { return "dns.subdomain-takeover" }
func (SubdomainTakeover) Category() core.Category { return core.CategoryDNS }
func (SubdomainTakeover) Mode() core.Mode         { return core.ModePassive }
func (SubdomainTakeover) Description() string {
	return "CNAME to a takeover-prone service with an unclaimed target"
}
func (SubdomainTakeover) OWASP() []string { return []string{"A05:2021"} }

func (SubdomainTakeover) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	dom := domain(t)
	if dom == "" {
		return nil, nil
	}
	r := resolverFrom(ctx)
	cname, err := cnameOf(ctx, r, dom)
	if err != nil || cname == "" {
		return nil, err
	}
	target := strings.TrimSuffix(strings.ToLower(cname), ".")
	var matched string
	for _, fp := range takeoverFingerprints {
		if strings.HasSuffix(target, fp) {
			matched = fp
			break
		}
	}
	if matched == "" {
		return nil, nil
	}
	addrs, err := r.LookupHost(ctx, cname)
	if err == nil && len(addrs) > 0 {
		return nil, nil // resource is live and presumably claimed
	}
	if err != nil && !isNoHost(err) {
		return nil, err
	}
	return []core.Finding{{
		Title:      "Possible subdomain takeover via " + matched,
		Category:   core.CategoryDNS,
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidencePossible,
		Asset:      asset(t, dom),
		Evidence:   core.Evidence{Matched: dom + " CNAME " + cname + " (unresolved, " + matched + ")"},
		CWE:        []string{"CWE-350"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: dom + " points at " + cname + " on a service (" + matched + ") known for subdomain takeover, and the target does not resolve.",
			Why:  "If the backing resource is unregistered, an attacker can claim it on that provider and serve their own content from your subdomain — used for phishing, cookie theft and bypassing same-site protections.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Either re-claim the resource on the provider, or delete the CNAME. Verify the record only after the resource is provisioned."},
			},
			Effort:     core.EffortM,
			References: []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"},
		},
	}}, nil
}

func cnameOf(ctx context.Context, r Resolver, dom string) (string, error) {
	return core.Memo(ctx, "dns.cname:"+dom, func() (string, error) {
		cname, err := r.LookupCNAME(ctx, dom)
		if err != nil {
			if isNoHost(err) {
				return "", nil
			}
			return "", err
		}
		return cname, nil
	})
}

// isNoHost reports whether err is a "no such host"/not-found DNS error, which
// the checks treat as "record absent", not a failure.
func isNoHost(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

func txtFix(name, value string) []core.Fix {
	return []core.Fix{
		{Stack: "generic", Language: "text", Code: "Add a DNS TXT record:\n" + name + ".  IN  TXT  \"" + value + "\""},
	}
}
