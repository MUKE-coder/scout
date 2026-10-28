package ports

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

// listener opens a TCP listener on localhost and returns its port.
func listener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestExposedServiceDetected(t *testing.T) {
	open := listener(t)
	closed := freePort(t) // nothing listening here
	ctx := WithServices(context.Background(), map[int]ServiceInfo{
		open:   {"Redis", core.SeverityHigh, "no auth"},
		closed: {"MongoDB", core.SeverityHigh, "no auth"},
	})
	got, err := ExposedServices{}.Run(ctx, core.Target{URL: "http://127.0.0.1", Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (only the open port): %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Port != open || f.Severity != core.SeverityHigh || f.Confidence != core.ConfidenceConfirmed {
		t.Fatalf("finding = %+v", f)
	}
	if f.Asset.Exposure != core.ExposureInternal {
		t.Fatalf("127.0.0.1 should be internal exposure, got %q", f.Asset.Exposure)
	}
}

func TestNoHostNoScan(t *testing.T) {
	got, err := ExposedServices{}.Run(context.Background(), core.Target{Repo: ".", Environment: core.EnvDev})
	if err != nil || got != nil {
		t.Fatalf("repo-only target: %v %v", got, err)
	}
}

func TestAllClosed(t *testing.T) {
	ctx := WithServices(context.Background(), map[int]ServiceInfo{freePort(t): {"Redis", core.SeverityHigh, "x"}})
	got, _ := ExposedServices{}.Run(ctx, core.Target{URL: "http://127.0.0.1", Environment: core.EnvDev})
	if len(got) != 0 {
		t.Fatalf("closed port should yield no finding: %+v", got)
	}
}

// freePort returns a port with nothing listening on it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_ = strconv.Itoa(p)
	return p
}
