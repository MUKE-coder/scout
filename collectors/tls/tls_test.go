package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/MUKE-coder/scout/core"
)

func scanCtx() context.Context {
	// TLS checks dial directly (no httpx client), so only the scan cache matters.
	return core.WithScanCache(context.Background())
}

// startTLS starts a raw TLS listener with the given config and min/max version,
// returning an https URL target pointing at it.
func startServer(t *testing.T, cfg *tls.Config) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, cfg)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })
	return core.Target{
		URL:         "https://" + ln.Addr().String(),
		Environment: core.EnvDev,
	}
}

// selfSigned builds a self-signed ECDSA cert for 127.0.0.1 valid over the
// given window.
func selfSigned(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// --- WeakProtocols ---

func TestWeakProtocols(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	t.Run("tls 1.0 flagged", func(t *testing.T) {
		tgt := startServer(t, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS13,
		})
		got, err := WeakProtocols{}.Run(scanCtx(), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium finding, got %+v", got)
		}
	})

	t.Run("tls 1.2 min is clean", func(t *testing.T) {
		tgt := startServer(t, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		})
		got, err := WeakProtocols{}.Run(scanCtx(), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings, got %+v", got)
		}
	})
}

// --- CertExpiry ---

func TestCertExpiry(t *testing.T) {
	t.Run("expired cert is tagged", func(t *testing.T) {
		cert := selfSigned(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
		tgt := startServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		got, err := CertExpiry{}.Run(scanCtx(), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !got[0].HasTag(core.TagExpiredCert) {
			t.Error("expired cert finding is missing TagExpiredCert")
		}
		if got[0].Severity != core.SeverityHigh {
			t.Errorf("severity = %s, want high", got[0].Severity)
		}
	})

	t.Run("expiring soon is low", func(t *testing.T) {
		cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
		tgt := startServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		got, err := CertExpiry{}.Run(scanCtx(), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityLow {
			t.Fatalf("want 1 low finding, got %+v", got)
		}
		if got[0].HasTag(core.TagExpiredCert) {
			t.Error("not-yet-expired cert should not carry TagExpiredCert")
		}
	})

	t.Run("healthy cert is clean", func(t *testing.T) {
		cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
		tgt := startServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		got, err := CertExpiry{}.Run(scanCtx(), tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings, got %+v", got)
		}
	})
}

// --- CertChain ---

func TestCertChain(t *testing.T) {
	// A self-signed cert fails chain verification (unknown authority).
	cert := selfSigned(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	tgt := startServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	got, err := CertChain{}.Run(scanCtx(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding for self-signed cert, got %d", len(got))
	}
	if len(got[0].CWE) == 0 || got[0].CWE[0] != "CWE-295" {
		t.Errorf("want CWE-295, got %v", got[0].CWE)
	}
}

// --- repo-only / non-https target ---

func TestNonHTTPSTargetNoFindings(t *testing.T) {
	ctx := scanCtx()
	tgt := core.Target{URL: "http://example.com", Environment: core.EnvDev}
	for _, c := range []core.Check{WeakProtocols{}, WeakCiphers{}, CertExpiry{}, CertChain{}, HSTSPreload{}} {
		got, err := c.Run(ctx, tgt)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.ID(), err)
		}
		if len(got) != 0 {
			t.Errorf("%s: want 0 findings on http target, got %d", c.ID(), len(got))
		}
	}
}
