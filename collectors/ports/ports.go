// Package ports detects risky back-end services that are reachable on the
// target's own host — exposed databases, caches, container APIs and remote
// shells that are usually meant to stay private. It performs a plain TCP
// connect (open / closed) to a curated list of well-known service ports and
// sends no payload and no exploit; it only observes whether the port
// accepts a connection. It scans only the target's host, honors ctx, and
// uses short timeouts.
package ports

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MUKE-coder/scout/core"
)

func init() { core.Register(ExposedServices{}) }

// ServiceInfo describes a well-known port worth flagging if it is reachable.
// Exported so callers (and the network sweep) can supply a custom port list.
type ServiceInfo struct {
	Name     string
	Severity core.Severity
	Why      string
}

// riskyServices is the curated list. These are back-end services that should
// almost never be reachable from where a scanner sits.
var riskyServices = map[int]ServiceInfo{
	2375:  {"Docker API (plaintext)", core.SeverityCritical, "An open Docker API grants remote control of the host — effectively root."},
	2376:  {"Docker API (TLS)", core.SeverityHigh, "The Docker API is reachable; ensure it requires client-certificate auth."},
	6379:  {"Redis", core.SeverityHigh, "Redis often ships with no authentication and allows data access or RCE via config."},
	27017: {"MongoDB", core.SeverityHigh, "An exposed MongoDB may allow unauthenticated read/write of all data."},
	9200:  {"Elasticsearch", core.SeverityHigh, "Elasticsearch exposes indices and, when scriptable, code execution."},
	11211: {"Memcached", core.SeverityHigh, "Memcached has no auth and is abused for data access and DDoS amplification."},
	5432:  {"PostgreSQL", core.SeverityMedium, "A database port should not be reachable from outside the app tier."},
	3306:  {"MySQL/MariaDB", core.SeverityMedium, "A database port should not be reachable from outside the app tier."},
	5984:  {"CouchDB", core.SeverityMedium, "An exposed CouchDB may allow unauthenticated access."},
	1433:  {"Microsoft SQL Server", core.SeverityMedium, "A database port should not be reachable from outside the app tier."},
	23:    {"Telnet", core.SeverityHigh, "Telnet is unencrypted; use SSH instead and close this port."},
	3389:  {"RDP", core.SeverityMedium, "Remote Desktop should sit behind a VPN, not be internet-reachable."},
	22:    {"SSH", core.SeverityLow, "SSH is reachable from the scanner; restrict it by firewall and disable password auth."},
}

type servicesKey struct{}

// WithServices overrides the port list (tests point it at a local listener).
func WithServices(ctx context.Context, s map[int]ServiceInfo) context.Context {
	return context.WithValue(ctx, servicesKey{}, s)
}

func servicesFrom(ctx context.Context) map[int]ServiceInfo {
	if s, ok := ctx.Value(servicesKey{}).(map[int]ServiceInfo); ok && s != nil {
		return s
	}
	return riskyServices
}

// ExposedServices flags reachable risky service ports on the target host.
type ExposedServices struct{}

func (ExposedServices) ID() string              { return "network.exposed-services" }
func (ExposedServices) Category() core.Category { return core.CategoryNetwork }
func (ExposedServices) Mode() core.Mode         { return core.ModeSafe }
func (ExposedServices) Description() string {
	return "Risky back-end services (DB, Redis, Docker API, SSH) are reachable on the target host"
}
func (ExposedServices) OWASP() []string { return []string{"A05:2021"} }

const (
	dialTimeout = 2 * time.Second
	maxParallel = 8
)

func (ExposedServices) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	host := t.Host()
	if host == "" {
		return nil, nil // nothing to scan for a repo-only target
	}
	exposure := core.ExposureInternet
	if t.IsLocal() {
		exposure = core.ExposureInternal
	}
	return ScanHost(ctx, host, exposure, t.Criticality), nil
}

// ScanHost connect-scans a single host's risky service ports and returns a
// finding per open port. It sends no payload (TCP connect only). Exported so the
// network sweep can reuse it across a CIDR range; the port list can be overridden
// for tests via WithServices(ctx, …).
func ScanHost(ctx context.Context, host string, exposure core.Exposure, criticality float64) []core.Finding {
	services := servicesFrom(ctx)

	type hit struct {
		port int
		svc  ServiceInfo
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits []hit
		sem  = make(chan struct{}, maxParallel)
	)
	for port, svc := range services {
		wg.Add(1)
		go func(port int, svc ServiceInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if dialOpen(ctx, host, port) {
				mu.Lock()
				hits = append(hits, hit{port, svc})
				mu.Unlock()
			}
		}(port, svc)
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].port < hits[j].port })

	out := make([]core.Finding, 0, len(hits))
	for _, h := range hits {
		addr := net.JoinHostPort(host, strconv.Itoa(h.port))
		out = append(out, core.Finding{
			Title:      fmt.Sprintf("%s reachable on port %d", h.svc.Name, h.port),
			Category:   core.CategoryNetwork,
			Severity:   h.svc.Severity,
			Confidence: core.ConfidenceConfirmed, // a successful TCP connect is definitive
			Asset:      core.Asset{Kind: core.AssetHost, Value: addr, Host: host, Port: h.port, Exposure: exposure, Criticality: criticality},
			Evidence:   core.Evidence{Notes: fmt.Sprintf("TCP connect to %s succeeded.", addr)},
			CWE:        []string{"CWE-668"},
			OWASP:      []string{"A05:2021"},
			Remediation: core.Remediation{
				What: h.svc.Why,
				Why:  "A service reachable from the scanner is reachable by others on that network path; back-end services should be bound to localhost or a private network and firewalled.",
				How: []core.Fix{
					{Stack: "generic", Language: "text", Code: fmt.Sprintf("Bind %s to 127.0.0.1 or a private interface, require authentication, and block port %d at the firewall for public ranges.", h.svc.Name, h.port)},
				},
				Effort:     core.EffortM,
				References: []string{"https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"},
			},
		})
	}
	return out
}

// dialOpen reports whether a TCP connection to host:port succeeds.
func dialOpen(ctx context.Context, host string, port int) bool {
	d := net.Dialer{Timeout: dialTimeout}
	c, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := d.DialContext(c, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
