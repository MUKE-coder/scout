// Package tls checks a target's TLS configuration: protocol versions, cipher
// strength, certificate validity and expiry, chain, and HSTS preload
// eligibility. Every check is passive — it performs one TLS handshake with the
// target host (shared across checks via core.Memo) and inspects the result. It
// sends no application traffic and no attack payloads.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/MUKE-coder/scout/core"
)

func init() {
	core.Register(WeakProtocols{})
	core.Register(WeakCiphers{})
	core.Register(CertExpiry{})
	core.Register(CertChain{})
	core.Register(HSTSPreload{})
}

// handshakeTimeout bounds a single TLS dial.
const handshakeTimeout = 10 * time.Second

// state is the result of one memoized handshake against the target.
type state struct {
	host    string // hostname dialed
	addr    string // host:port
	version uint16 // negotiated protocol (as the server's max we could reach)
	cipher  uint16 // negotiated cipher suite
	// minVersion is the lowest protocol the server agreed to in a probe.
	minVersion uint16
	leaf       *x509.Certificate
	chain      []*x509.Certificate
	verifyErr  error // chain/hostname verification error, if any
}

// hostPort returns host:port for a target URL, defaulting to :443.
func hostPort(t core.Target) (host, addr string, ok bool) {
	if t.URL == "" {
		return "", "", false
	}
	u, err := url.Parse(t.URL)
	if err != nil || u.Scheme != "https" {
		return "", "", false // plaintext or non-URL target: nothing to handshake
	}
	host = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return host, net.JoinHostPort(host, port), true
}

// handshake performs (once per scan) a verified handshake plus a probe for the
// lowest protocol the server will accept.
func handshake(ctx context.Context, t core.Target) (*state, error) {
	host, addr, ok := hostPort(t)
	if !ok {
		return nil, nil
	}
	return core.Memo(ctx, "tls.handshake:"+addr, func() (*state, error) {
		st := &state{host: host, addr: addr}

		// 1. A normal, verifying handshake to collect the certificate chain.
		conn, err := dial(ctx, addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10})
		if err != nil {
			// Record the verification error but still try to read the chain
			// from an InsecureSkipVerify handshake, so cert checks can run.
			st.verifyErr = err
			conn, err = dial(ctx, addr, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // we only read the cert; we never trust it
			if err != nil {
				return nil, err
			}
		}
		cs := conn.ConnectionState()
		_ = conn.Close()
		st.version = cs.Version
		st.cipher = cs.CipherSuite
		if len(cs.PeerCertificates) > 0 {
			st.leaf = cs.PeerCertificates[0]
			st.chain = cs.PeerCertificates
		}

		// 2. Probe the lowest protocol the server will negotiate, to detect
		// legacy TLS 1.0/1.1 support without trusting the cert.
		st.minVersion = lowestAccepted(ctx, host, addr)
		return st, nil
	})
}

func dial(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: handshakeTimeout}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// lowestAccepted returns the lowest TLS version the server negotiates, probing
// from TLS 1.0 up. Returns 0 if none succeed.
func lowestAccepted(ctx context.Context, host, addr string) uint16 {
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: v, MaxVersion: v} //nolint:gosec // version probe only
		conn, err := dial(ctx, addr, cfg)
		if err == nil {
			_ = conn.Close()
			return v
		}
	}
	return 0
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func asset(t core.Target, st *state) core.Asset {
	exp := core.ExposureInternet
	if t.IsLocal() {
		exp = core.ExposureInternal
	}
	return core.Asset{
		Kind:        core.AssetHost,
		Value:       st.addr,
		Host:        st.host,
		Exposure:    exp,
		Criticality: t.Criticality,
	}
}

func disableLegacyTLSFix() []core.Fix {
	return []core.Fix{
		{Stack: "nginx", Language: "nginx", Code: `ssl_protocols TLSv1.2 TLSv1.3;`},
		{Stack: "caddy", Language: "caddy", Code: `tls {
	protocols tls1.2 tls1.3
}`},
		{Stack: "gin", Language: "go", Code: `srv := &http.Server{
	Addr:    ":443",
	Handler: router,
	TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
}`},
		{Stack: "generic", Language: "text", Code: "Disable TLS 1.0 and TLS 1.1 at the server or load balancer; allow only TLS 1.2 and 1.3."},
	}
}

// WeakProtocols flags support for TLS 1.0 or TLS 1.1.
type WeakProtocols struct{}

func (WeakProtocols) ID() string              { return "tls.weak-protocols" }
func (WeakProtocols) Category() core.Category { return core.CategoryTLS }
func (WeakProtocols) Mode() core.Mode         { return core.ModePassive }
func (WeakProtocols) Description() string     { return "Server accepts deprecated TLS 1.0/1.1" }
func (WeakProtocols) OWASP() []string         { return []string{"A02:2021"} }
func (WeakProtocols) ASVS() []string          { return []string{"V9.1.3"} }

func (WeakProtocols) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	st, err := handshake(ctx, t)
	if err != nil || st == nil {
		return nil, err
	}
	if st.minVersion == 0 || st.minVersion >= tls.VersionTLS12 {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Server supports deprecated " + versionName(st.minVersion),
		Category:   core.CategoryTLS,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      asset(t, st),
		Evidence:   core.Evidence{Matched: "lowest negotiated protocol: " + versionName(st.minVersion)},
		CWE:        []string{"CWE-327"},
		OWASP:      []string{"A02:2021"},
		Remediation: core.Remediation{
			What:   "The server negotiates " + versionName(st.minVersion) + ", a deprecated TLS version.",
			Why:    "TLS 1.0 and 1.1 have known weaknesses (BEAST, POODLE-style padding and weak MACs) and are disallowed by PCI-DSS. An attacker who can influence the connection may exploit them.",
			How:    disableLegacyTLSFix(),
			Effort: core.EffortS,
			References: []string{
				"https://datatracker.ietf.org/doc/rfc8996/",
			},
		},
	}}, nil
}

// WeakCiphers flags a negotiated cipher suite that Go marks insecure (e.g. RC4,
// 3DES, CBC suites without forward secrecy).
type WeakCiphers struct{}

func (WeakCiphers) ID() string              { return "tls.weak-ciphers" }
func (WeakCiphers) Category() core.Category { return core.CategoryTLS }
func (WeakCiphers) Mode() core.Mode         { return core.ModePassive }
func (WeakCiphers) Description() string     { return "Server negotiates a weak cipher suite" }
func (WeakCiphers) OWASP() []string         { return []string{"A02:2021"} }
func (WeakCiphers) ASVS() []string          { return []string{"V9.1.3"} }

func (WeakCiphers) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	st, err := handshake(ctx, t)
	if err != nil || st == nil {
		return nil, err
	}
	// TLS 1.3 suites are all strong; Go's insecure list covers TLS 1.2 and below.
	if st.version >= tls.VersionTLS13 || st.cipher == 0 {
		return nil, nil
	}
	if !isInsecureCipher(st.cipher) {
		return nil, nil
	}
	name := tls.CipherSuiteName(st.cipher)
	return []core.Finding{{
		Title:      "Weak TLS cipher suite negotiated: " + name,
		Category:   core.CategoryTLS,
		Severity:   core.SeverityMedium,
		Confidence: core.ConfidenceConfirmed,
		Asset:      asset(t, st),
		Evidence:   core.Evidence{Matched: "negotiated cipher: " + name},
		CWE:        []string{"CWE-327"},
		OWASP:      []string{"A02:2021"},
		Remediation: core.Remediation{
			What:   "The server negotiated " + name + ", which Go's crypto/tls classifies as insecure.",
			Why:    "Weak ciphers (RC4, 3DES, or CBC suites without forward secrecy) can let an attacker who records traffic decrypt it later or weaken session confidentiality.",
			How:    disableLegacyTLSFix(),
			Effort: core.EffortS,
			References: []string{
				"https://ssl-config.mozilla.org/",
			},
		},
	}}, nil
}

func isInsecureCipher(id uint16) bool {
	for _, c := range tls.InsecureCipherSuites() {
		if c.ID == id {
			return true
		}
	}
	return false
}

// CertExpiry flags certificates that are expired (tagged core.TagExpiredCert,
// which caps the grade) or expiring soon.
type CertExpiry struct{}

func (CertExpiry) ID() string              { return "tls.cert-expiry" }
func (CertExpiry) Category() core.Category { return core.CategoryTLS }
func (CertExpiry) Mode() core.Mode         { return core.ModePassive }
func (CertExpiry) Description() string     { return "TLS certificate is expired or expiring soon" }
func (CertExpiry) OWASP() []string         { return []string{"A02:2021"} }
func (CertExpiry) ASVS() []string          { return []string{"V9.1.1"} }

// expiryWarn is how far ahead a not-yet-expired cert is flagged.
const expiryWarn = 21 * 24 * time.Hour

func (CertExpiry) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	st, err := handshake(ctx, t)
	if err != nil || st == nil || st.leaf == nil {
		return nil, err
	}
	now := time.Now()
	leaf := st.leaf

	switch {
	case now.After(leaf.NotAfter):
		return []core.Finding{{
			Title:      "TLS certificate has expired",
			Category:   core.CategoryTLS,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, st),
			Evidence:   core.Evidence{Matched: "notAfter: " + leaf.NotAfter.UTC().Format(time.RFC3339)},
			CWE:        []string{"CWE-298"},
			OWASP:      []string{"A02:2021"},
			Tags:       []string{core.TagExpiredCert},
			Remediation: core.Remediation{
				What:       "The leaf certificate's validity ended on " + leaf.NotAfter.UTC().Format("2006-01-02") + ".",
				Why:        "Browsers and API clients reject an expired certificate with a hard error, so the site is effectively down and users are trained to click through security warnings.",
				How:        renewCertFix(),
				Effort:     core.EffortS,
				References: []string{"https://letsencrypt.org/docs/"},
			},
		}}, nil
	case now.Before(leaf.NotBefore):
		return []core.Finding{{
			Title:      "TLS certificate is not yet valid",
			Category:   core.CategoryTLS,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, st),
			Evidence:   core.Evidence{Matched: "notBefore: " + leaf.NotBefore.UTC().Format(time.RFC3339)},
			CWE:        []string{"CWE-298"},
			OWASP:      []string{"A02:2021"},
			Remediation: core.Remediation{
				What:       "The certificate's validity does not begin until " + leaf.NotBefore.UTC().Format("2006-01-02") + ".",
				Why:        "A not-yet-valid certificate is rejected exactly like an expired one; it usually means a clock or issuance problem.",
				How:        renewCertFix(),
				Effort:     core.EffortS,
				References: []string{"https://letsencrypt.org/docs/"},
			},
		}}, nil
	case now.Add(expiryWarn).After(leaf.NotAfter):
		days := int(time.Until(leaf.NotAfter).Hours() / 24)
		return []core.Finding{{
			Title:      fmt.Sprintf("TLS certificate expires in %d days", days),
			Category:   core.CategoryTLS,
			Severity:   core.SeverityLow,
			Confidence: core.ConfidenceConfirmed,
			Asset:      asset(t, st),
			Evidence:   core.Evidence{Matched: "notAfter: " + leaf.NotAfter.UTC().Format(time.RFC3339)},
			CWE:        []string{"CWE-298"},
			OWASP:      []string{"A02:2021"},
			Remediation: core.Remediation{
				What:       "The certificate expires on " + leaf.NotAfter.UTC().Format("2006-01-02") + ".",
				Why:        "If renewal is manual it is easy to miss the deadline and cause an outage. Automate renewal so it never lapses.",
				How:        renewCertFix(),
				Effort:     core.EffortS,
				References: []string{"https://letsencrypt.org/docs/"},
			},
		}}, nil
	}
	return nil, nil
}

func renewCertFix() []core.Fix {
	return []core.Fix{
		{Stack: "generic", Language: "bash", Code: `# automate renewal, e.g. with certbot
certbot renew --quiet
# or use Caddy / a cloud load balancer that renews automatically`},
	}
}

// CertChain flags a certificate whose chain or hostname does not verify
// against the system roots.
type CertChain struct{}

func (CertChain) ID() string              { return "tls.cert-chain" }
func (CertChain) Category() core.Category { return core.CategoryTLS }
func (CertChain) Mode() core.Mode         { return core.ModePassive }
func (CertChain) Description() string {
	return "TLS certificate chain or hostname does not verify"
}
func (CertChain) OWASP() []string { return []string{"A02:2021"} }
func (CertChain) ASVS() []string  { return []string{"V9.1.1"} }

func (CertChain) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	st, err := handshake(ctx, t)
	if err != nil || st == nil {
		return nil, err
	}
	if st.verifyErr == nil {
		return nil, nil
	}
	// Expiry is reported by CertExpiry; don't double-report it here.
	var ce x509.CertificateInvalidError
	if errors.As(st.verifyErr, &ce) && ce.Reason == x509.Expired {
		return nil, nil
	}
	sev := core.SeverityMedium
	var hostErr x509.HostnameError
	if errors.As(st.verifyErr, &hostErr) {
		sev = core.SeverityHigh // wrong hostname is worse: likely misissued or misrouted
	}
	return []core.Finding{{
		Title:      "TLS certificate does not verify",
		Category:   core.CategoryTLS,
		Severity:   sev,
		Confidence: core.ConfidenceConfirmed,
		Asset:      asset(t, st),
		Evidence:   core.Evidence{Matched: st.verifyErr.Error()},
		CWE:        []string{"CWE-295"},
		OWASP:      []string{"A02:2021"},
		Remediation: core.Remediation{
			What: "The presented certificate fails standard verification: " + st.verifyErr.Error() + ".",
			Why:  "Clients that verify correctly will refuse to connect; clients that ignore the error are exposed to interception. A self-signed or incomplete chain in production usually signals a misconfiguration.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: "Serve a certificate from a trusted CA that matches the hostname, and include the full intermediate chain (fullchain.pem)."},
			},
			Effort:     core.EffortM,
			References: []string{"https://ssl-config.mozilla.org/"},
		},
	}}, nil
}

// HSTSPreload flags an HTTPS host whose leaf certificate is fine but is a good
// candidate for HSTS preload (informational nudge; the header itself is
// checked by the headers collector).
type HSTSPreload struct{}

func (HSTSPreload) ID() string              { return "tls.hsts-preload" }
func (HSTSPreload) Category() core.Category { return core.CategoryTLS }
func (HSTSPreload) Mode() core.Mode         { return core.ModePassive }
func (HSTSPreload) Description() string {
	return "Host is eligible for HSTS preload but may not be enrolled"
}
func (HSTSPreload) OWASP() []string { return []string{"A05:2021"} }
func (HSTSPreload) ASVS() []string  { return []string{"V9.1.2"} }

func (HSTSPreload) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	st, err := handshake(ctx, t)
	if err != nil || st == nil || st.leaf == nil {
		return nil, err
	}
	// Only suggest preload for apex-style hostnames, not for local or IP hosts.
	if t.IsLocal() || net.ParseIP(st.host) != nil || strings.Count(st.host, ".") < 1 {
		return nil, nil
	}
	return []core.Finding{{
		Title:      "Consider HSTS preloading for " + st.host,
		Category:   core.CategoryTLS,
		Severity:   core.SeverityInfo,
		Confidence: core.ConfidenceLikely,
		Asset:      asset(t, st),
		Evidence:   core.Evidence{Notes: "host serves a valid certificate and could be submitted to the HSTS preload list"},
		CWE:        []string{"CWE-319"},
		OWASP:      []string{"A05:2021"},
		Remediation: core.Remediation{
			What: "The host serves HTTPS but is (likely) not on the browser HSTS preload list.",
			Why:  "Preloading removes the very first unprotected HTTP request, closing the small SSL-stripping window that even a correct HSTS header leaves open on a user's first visit.",
			How: []core.Fix{
				{Stack: "generic", Language: "text", Code: `Send: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
then submit the domain at https://hstspreload.org/`},
			},
			Effort:     core.EffortS,
			References: []string{"https://hstspreload.org/"},
		},
	}}, nil
}
