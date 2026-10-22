package dns

import (
	"context"
	"net"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// fakeResolver is a table-driven Resolver for tests.
type fakeResolver struct {
	txt   map[string][]string
	cname map[string]string
	hosts map[string][]string
	caa   map[string][]string
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if v, ok := f.cname[host]; ok {
		return v, nil
	}
	return host, nil // net.LookupCNAME returns the host itself when there's no CNAME
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if v, ok := f.hosts[host]; ok && len(v) > 0 {
		return v, nil
	}
	return nil, notFound(host)
}

func (f fakeResolver) LookupCAA(_ context.Context, name string) ([]string, error) {
	if v, ok := f.caa[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func ctxWith(r Resolver) context.Context {
	return WithResolver(core.WithScanCache(context.Background()), r)
}

func tgt() core.Target {
	return core.Target{URL: "https://example.com", Environment: core.EnvProd}
}

func TestSPF(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		got, err := SPF{}.Run(ctxWith(fakeResolver{}), tgt())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium, got %+v", got)
		}
	})
	t.Run("present and strict", func(t *testing.T) {
		r := fakeResolver{txt: map[string][]string{"example.com": {"v=spf1 include:_spf.google.com -all"}}}
		got, _ := SPF{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
	t.Run("plus all is flagged", func(t *testing.T) {
		r := fakeResolver{txt: map[string][]string{"example.com": {"v=spf1 +all"}}}
		got, _ := SPF{}.Run(ctxWith(r), tgt())
		if len(got) != 1 {
			t.Fatalf("want 1, got %+v", got)
		}
	})
}

func TestDMARC(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		got, _ := DMARC{}.Run(ctxWith(fakeResolver{}), tgt())
		if len(got) != 1 || got[0].Severity != core.SeverityMedium {
			t.Fatalf("want 1 medium, got %+v", got)
		}
	})
	t.Run("p=none is low", func(t *testing.T) {
		r := fakeResolver{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=none"}}}
		got, _ := DMARC{}.Run(ctxWith(r), tgt())
		if len(got) != 1 || got[0].Severity != core.SeverityLow {
			t.Fatalf("want 1 low, got %+v", got)
		}
	})
	t.Run("p=reject is clean", func(t *testing.T) {
		r := fakeResolver{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}}
		got, _ := DMARC{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestDKIM(t *testing.T) {
	t.Run("none found is possible", func(t *testing.T) {
		got, _ := DKIM{}.Run(ctxWith(fakeResolver{}), tgt())
		if len(got) != 1 || got[0].Confidence != core.ConfidencePossible {
			t.Fatalf("want 1 possible, got %+v", got)
		}
	})
	t.Run("key on google selector", func(t *testing.T) {
		r := fakeResolver{txt: map[string][]string{
			"google._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIGf..."},
		}}
		got, _ := DKIM{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestCAA(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		r := fakeResolver{caa: map[string][]string{"example.com": {`0 issue "letsencrypt.org"`}}}
		got, _ := CAA{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		got, _ := CAA{}.Run(ctxWith(fakeResolver{}), tgt())
		if len(got) != 1 {
			t.Fatalf("want 1, got %+v", got)
		}
	})
	t.Run("unsupported resolver stays silent", func(t *testing.T) {
		// The system resolver returns errCAAUnsupported; simulate by using
		// the real sysResolver.
		got, err := CAA{}.Run(core.WithScanCache(context.Background()), tgt())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want 0 findings when CAA is unsupported, got %+v", got)
		}
	})
}

func TestDanglingCNAME(t *testing.T) {
	t.Run("dangling", func(t *testing.T) {
		r := fakeResolver{cname: map[string]string{"example.com": "old-app.herokuapp.com."}}
		got, _ := DanglingCNAME{}.Run(ctxWith(r), tgt())
		if len(got) != 1 {
			t.Fatalf("want 1, got %+v", got)
		}
	})
	t.Run("resolving cname is clean", func(t *testing.T) {
		r := fakeResolver{
			cname: map[string]string{"example.com": "app.herokuapp.com."},
			hosts: map[string][]string{"app.herokuapp.com.": {"52.1.2.3"}},
		}
		got, _ := DanglingCNAME{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
	t.Run("no cname is clean", func(t *testing.T) {
		got, _ := DanglingCNAME{}.Run(ctxWith(fakeResolver{}), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestSubdomainTakeover(t *testing.T) {
	t.Run("unclaimed github pages", func(t *testing.T) {
		r := fakeResolver{cname: map[string]string{"example.com": "someuser.github.io."}}
		got, _ := SubdomainTakeover{}.Run(ctxWith(r), tgt())
		if len(got) != 1 || got[0].Severity != core.SeverityHigh {
			t.Fatalf("want 1 high, got %+v", got)
		}
	})
	t.Run("non-fingerprinted cname ignored", func(t *testing.T) {
		r := fakeResolver{cname: map[string]string{"example.com": "internal.corp.example.net."}}
		got, _ := SubdomainTakeover{}.Run(ctxWith(r), tgt())
		if len(got) != 0 {
			t.Fatalf("want 0, got %+v", got)
		}
	})
}

func TestNonDomainTargetNoFindings(t *testing.T) {
	// A bare IP and a repo-only target have no DNS posture.
	for _, tgt := range []core.Target{
		{URL: "https://127.0.0.1:8443", Environment: core.EnvDev},
		{Repo: ".", Environment: core.EnvDev},
		{URL: "http://localhost:8080", Environment: core.EnvDev},     // single-label, not in DNS
		{URL: "http://api.localhost:8080", Environment: core.EnvDev}, // *.localhost
	} {
		ctx := core.WithScanCache(context.Background())
		for _, c := range []core.Check{SPF{}, DMARC{}, DKIM{}, CAA{}, DanglingCNAME{}, SubdomainTakeover{}} {
			got, err := c.Run(ctx, tgt)
			if err != nil {
				t.Errorf("%s: %v", c.ID(), err)
			}
			if len(got) != 0 {
				t.Errorf("%s: want 0 findings for %v, got %d", c.ID(), tgt, len(got))
			}
		}
	}
}
