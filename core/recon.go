package core

// Recon is the reconnaissance gathered for a target's domain — the passive
// "information gathering" step of a pen test (WHOIS, DNS records, subdomains).
// It is informational context, not findings.
type Recon struct {
	Domain     string   `json:"domain,omitempty"`
	WHOIS      *WHOIS   `json:"whois,omitempty"`
	DNS        *DNS     `json:"dns,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
}

// WHOIS is the domain registration data worth surfacing.
type WHOIS struct {
	Registrar   string   `json:"registrar,omitempty"`
	Org         string   `json:"org,omitempty"`
	Created     string   `json:"created,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	Status      []string `json:"status,omitempty"`
}

// DNS holds the records recon resolves for the domain.
type DNS struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	PTR   []string `json:"ptr,omitempty"` // reverse DNS of the primary A record
}
