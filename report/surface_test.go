package report

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func sf(kind core.AssetKind, value, host string, port int, sev core.Severity, status core.Status) core.Finding {
	return core.Finding{Severity: sev, Status: status, Asset: core.Asset{Kind: kind, Value: value, Host: host, Port: port}}
}

func find(nodes []*Node, label string) *Node {
	for _, n := range nodes {
		if n.Label == label {
			return n
		}
		if c := find(n.Children, label); c != nil {
			return c
		}
	}
	return nil
}

func TestSurfaceTree(t *testing.T) {
	scans := []core.ScanResult{{
		Target: core.Target{Name: "shop", URL: "https://shop.example.co.uk",
			Routes: []core.Route{{Method: "get", Path: "/health"}}},
		Findings: []core.Finding{
			sf(core.AssetURL, "https://shop.example.co.uk/", "", 0, core.SeverityLow, core.StatusOpen),
			sf(core.AssetURL, "https://shop.example.co.uk/admin", "", 0, core.SeverityHigh, core.StatusOpen),
			sf(core.AssetURL, "https://api.example.co.uk:8443/v1", "", 0, core.SeverityMedium, core.StatusOpen),
			sf(core.AssetHost, "10.0.0.5:6379", "10.0.0.5", 6379, core.SeverityCritical, core.StatusOpen),
			sf(core.AssetURL, "https://shop.example.co.uk/old", "", 0, core.SeverityCritical, core.StatusAcceptedRisk),
			sf(core.AssetFile, "main.go:3", "", 0, core.SeverityHigh, core.StatusOpen), // not network surface
		},
	}}
	roots := Surface(scans)

	domain := find(roots, "example.co.uk")
	if domain == nil || domain.Kind != NodeDomain {
		t.Fatalf("public-suffix-aware domain missing: %+v", roots)
	}
	if domain.Open != 3 || domain.Worst == nil || *domain.Worst != core.SeverityHigh {
		t.Fatalf("domain rollup open=%d worst=%v", domain.Open, domain.Worst)
	}
	if len(domain.Children) != 2 || domain.Children[0].Label != "shop.example.co.uk" {
		t.Fatalf("hosts should sort worst first: %+v", domain.Children)
	}
	svc := find(roots, "https :443")
	if svc == nil || svc.Open != 2 {
		t.Fatalf("service = %+v", svc)
	}
	if find(roots, "/admin") == nil || find(roots, "GET /health") == nil {
		t.Fatal("route from finding or route table missing")
	}
	if old := find(roots, "/old"); old == nil || old.Worst != nil || old.Open != 0 {
		t.Fatalf("accepted-risk finding should not color the node: %+v", old)
	}
	if ip := find(roots, "10.0.0.5"); ip == nil || ip.Kind != NodeDomain {
		t.Fatalf("IP hosts are their own root: %+v", ip)
	}
	if redis := find(roots, ":6379"); redis == nil || redis.Worst == nil || *redis.Worst != core.SeverityCritical {
		t.Fatalf("host:port service = %+v", redis)
	}
	if find(roots, "main.go:3") != nil {
		t.Fatal("file assets are not network surface")
	}
}
