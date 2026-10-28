// Package netsweep scans a whole network range (CIDR) for reachable risky
// services, host by host. It expands the target's Network (e.g. 192.168.1.0/24)
// to its host addresses and connect-scans each with the shared port scanner —
// TCP connect only, no payloads. Use it to find exposed databases, Docker APIs,
// SSH and remote shells across a LAN you are authorized to test.
package netsweep

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/MUKE-coder/scout/collectors/ports"
	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(Sweep{}) }

// CheckID is the id of the sweep check, so the CLI can restrict a network target
// to just this check.
const CheckID = "network.sweep"

// maxHosts caps a single sweep so a careless prefix (e.g. /8) cannot launch a
// multi-million-host scan. A /16 (65 534 hosts) is the largest allowed.
const maxHosts = 1 << 16

// hostParallel is how many hosts are scanned at once (each host also scans its
// ports concurrently via ports.ScanHost).
const hostParallel = 64

// Sweep flags risky services reachable across a CIDR range.
type Sweep struct{}

func (Sweep) ID() string              { return CheckID }
func (Sweep) Category() core.Category { return core.CategoryNetwork }
func (Sweep) Mode() core.Mode         { return core.ModeSafe }
func (Sweep) Description() string {
	return "Risky back-end services are reachable on hosts across a network range"
}
func (Sweep) OWASP() []string { return []string{"A05:2021"} }

func (Sweep) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	if t.Network == "" {
		return nil, nil
	}
	hosts, err := Hosts(t.Network)
	if err != nil {
		return nil, err
	}
	// A CIDR range is, by definition, not a single host; treat its findings as
	// internal exposure (reachable from where the scanner sits on that network).
	exposure := core.ExposureInternal

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []core.Finding
		sem = make(chan struct{}, hostParallel)
	)
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if fs := ports.ScanHost(ctx, host, exposure, t.Criticality); len(fs) > 0 {
				mu.Lock()
				out = append(out, fs...)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return out, nil
}

// Hosts expands a CIDR to the host addresses to scan. For an IPv4 prefix shorter
// than /31 the network and broadcast addresses are skipped. The count is capped
// at maxHosts.
func Hosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if n := uint64(1) << uint(bits-ones); n > maxHosts {
		return nil, fmt.Errorf("range %s has %d addresses; the maximum is %d (use a /%d or smaller)",
			cidr, n, maxHosts, bits-16)
	}

	var ips []string
	for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Drop network and broadcast for IPv4 ranges wider than a point-to-point /31.
	if v4 := ipnet.IP.To4(); v4 != nil && bits-ones >= 2 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

// inc increments an IP address in place.
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
