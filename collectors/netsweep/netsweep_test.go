package netsweep

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/MUKE-coder/scout/collectors/ports"
	"github.com/MUKE-coder/scout/core"
)

func TestHosts(t *testing.T) {
	cases := []struct {
		cidr    string
		count   int
		wantErr bool
	}{
		{"192.168.1.0/30", 2, false}, // 4 addrs − network − broadcast
		{"192.168.1.0/24", 254, false},
		{"10.0.0.5/32", 1, false},    // single host
		{"192.168.1.0/31", 2, false}, // point-to-point, no trim
		{"10.0.0.0/8", 0, true},      // too large
		{"nope", 0, true},            // invalid
	}
	for _, c := range cases {
		got, err := Hosts(c.cidr)
		if c.wantErr {
			if err == nil {
				t.Errorf("Hosts(%q): expected error", c.cidr)
			}
			continue
		}
		if err != nil {
			t.Errorf("Hosts(%q): %v", c.cidr, err)
			continue
		}
		if len(got) != c.count {
			t.Errorf("Hosts(%q) = %d hosts, want %d", c.cidr, len(got), c.count)
		}
	}
	// A /30 must exclude the network and broadcast addresses.
	got, _ := Hosts("192.168.1.0/30")
	for _, ip := range got {
		if ip == "192.168.1.0" || ip == "192.168.1.3" {
			t.Errorf("network/broadcast not excluded: %v", got)
		}
	}
}

func TestSweepFindsOpenService(t *testing.T) {
	// A listener stands in for a risky service; point the scanner at its port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])

	ctx := ports.WithServices(context.Background(), map[int]ports.ServiceInfo{
		port: {Name: "Fake DB", Severity: core.SeverityHigh, Why: "test service"},
	})

	got, err := Sweep{}.Run(ctx, core.Target{Name: "lo", Network: "127.0.0.1/32", Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding for the open port, got %d: %+v", len(got), got)
	}
	if got[0].Asset.Host != "127.0.0.1" || got[0].Asset.Port != port {
		t.Errorf("finding asset = %+v", got[0].Asset)
	}
}

func TestSweepNoNetwork(t *testing.T) {
	got, err := Sweep{}.Run(context.Background(), core.Target{URL: "https://x", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("non-network target should be a no-op: %v %v", got, err)
	}
}
