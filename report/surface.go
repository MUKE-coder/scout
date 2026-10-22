package report

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/scoring"
)

// Node kinds in the attack-surface tree.
const (
	NodeDomain  = "domain"
	NodeHost    = "host"
	NodeService = "service"
	NodeRoute   = "route"
)

// Node is one point of the attack surface: domain → host → service → route.
type Node struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Worst    *core.Severity `json:"worst,omitempty"` // worst open severity here or below
	Open     int            `json:"open"`            // open findings here or below
	Children []*Node        `json:"children,omitempty"`
}

// Surface builds the attack-surface tree from scans (normally the latest
// scan of each target). URL, route and host:port assets become nodes;
// file and container assets are not network surface and are left out.
// A target's route table (from scout.Mount) adds routes without findings.
func Surface(scans []core.ScanResult) []*Node {
	b := &surfaceBuilder{index: map[string]*Node{}}
	for _, sc := range scans {
		if u, err := url.Parse(sc.Target.URL); err == nil && u.Hostname() != "" {
			svc := b.service(u.Hostname(), portOf(u), u.Scheme)
			for _, r := range sc.Target.Routes {
				b.child(svc, NodeRoute, strings.ToUpper(r.Method)+" "+r.Path)
			}
		}
		for _, f := range sc.Findings {
			n := b.forAsset(f.Asset)
			if n == nil {
				continue
			}
			if scoring.Counts(f) {
				b.mark(n, f.Severity)
			}
		}
	}
	for _, d := range b.roots {
		rollUp(d)
		sortTree(d)
	}
	sort.Slice(b.roots, func(i, j int) bool { return b.roots[i].Label < b.roots[j].Label })
	return b.roots
}

type surfaceBuilder struct {
	roots []*Node
	index map[string]*Node
}

func (b *surfaceBuilder) node(id, kind, label string, parent *Node) *Node {
	if n, ok := b.index[id]; ok {
		return n
	}
	n := &Node{ID: id, Kind: kind, Label: label}
	b.index[id] = n
	if parent == nil {
		b.roots = append(b.roots, n)
	} else {
		parent.Children = append(parent.Children, n)
	}
	return n
}

func (b *surfaceBuilder) host(name string) *Node {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain := name
	if net.ParseIP(name) == nil && name != "localhost" {
		if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			domain = d
		}
	}
	d := b.node("d:"+domain, NodeDomain, domain, nil)
	return b.node("h:"+name, NodeHost, name, d)
}

func (b *surfaceBuilder) service(host string, port int, scheme string) *Node {
	h := b.host(host)
	label := ":" + strconv.Itoa(port)
	if scheme != "" {
		label = scheme + " " + label
	}
	return b.node("s:"+h.Label+":"+strconv.Itoa(port), NodeService, label, h)
}

func (b *surfaceBuilder) child(parent *Node, kind, label string) *Node {
	return b.node(parent.ID+"|"+label, kind, label, parent)
}

// forAsset places an asset in the tree and returns its node.
func (b *surfaceBuilder) forAsset(a core.Asset) *Node {
	switch a.Kind {
	case core.AssetURL:
		u, err := url.Parse(a.Value)
		if err != nil || u.Hostname() == "" {
			return nil
		}
		svc := b.service(u.Hostname(), portOf(u), u.Scheme)
		path := u.EscapedPath()
		if path == "" || path == "/" {
			return svc
		}
		return b.child(svc, NodeRoute, path)
	case core.AssetRoute:
		host := a.Host
		if host == "" {
			return nil
		}
		svc := b.service(host, max(a.Port, 0), "")
		return b.child(svc, NodeRoute, strings.TrimSpace(strings.ToUpper(a.Method)+" "+a.Path))
	case core.AssetHost:
		if a.Host == "" {
			return nil
		}
		if a.Port > 0 {
			return b.service(a.Host, a.Port, "")
		}
		return b.host(a.Host)
	case core.AssetDomain:
		host := a.Host
		if host == "" {
			host = a.Value
		}
		return b.host(host)
	}
	return nil // files and containers are not network surface
}

func (b *surfaceBuilder) mark(n *Node, sev core.Severity) {
	n.Open++
	if n.Worst == nil || sev > *n.Worst {
		s := sev
		n.Worst = &s
	}
}

// rollUp propagates open counts and worst severity from children.
func rollUp(n *Node) {
	for _, c := range n.Children {
		rollUp(c)
		n.Open += c.Open
		if c.Worst != nil && (n.Worst == nil || *c.Worst > *n.Worst) {
			s := *c.Worst
			n.Worst = &s
		}
	}
}

// sortTree orders children worst first, then by label.
func sortTree(n *Node) {
	sort.SliceStable(n.Children, func(i, j int) bool {
		a, b := n.Children[i], n.Children[j]
		as, bs := sevRank(a.Worst), sevRank(b.Worst)
		if as != bs {
			return as > bs
		}
		return a.Label < b.Label
	})
	for _, c := range n.Children {
		sortTree(c)
	}
}

func sevRank(s *core.Severity) int {
	if s == nil {
		return -1
	}
	return int(*s)
}

func portOf(u *url.URL) int {
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
