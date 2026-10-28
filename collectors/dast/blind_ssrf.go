package dast

import (
	"context"
	"os"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/oob"
)

// oobGrace is how long the blind-SSRF check waits for callbacks after injecting
// all payloads. Overridable in tests.
var oobGrace = 4 * time.Second

// BlindSSRF confirms server-side request forgery out-of-band: it injects a URL
// pointing at Scout's own OAST listener into candidate parameters and reports a
// parameter when the target calls the listener back. It confirms the *blind*
// case the reflected SSRF check cannot — where the fetched response never returns
// to the client. Detection only: Scout observes the callback, it does not exploit.
//
// Reachability: the listener must be reachable by the target. For a localhost
// target it just works; for a remote target, set SCOUT_OOB_ADDR to a base URL the
// target can reach (e.g. http://your-host:9999), and Scout binds that port.
type BlindSSRF struct{}

func (BlindSSRF) ID() string              { return "app.blind-ssrf" }
func (BlindSSRF) Category() core.Category { return core.CategoryApp }
func (BlindSSRF) Mode() core.Mode         { return core.ModeActive }
func (BlindSSRF) Description() string {
	return "A parameter triggers a blind server-side request, confirmed out-of-band (OAST)"
}
func (BlindSSRF) OWASP() []string { return []string{"A10:2021"} }
func (BlindSSRF) ASVS() []string  { return []string{"V5.2.6"} }

func (c BlindSSRF) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	spots := append(allParams(res), gather(targetsFor(res), urlParams)...)
	if len(spots) == 0 {
		return nil, nil
	}

	lis, err := oob.Start(ctx, os.Getenv("SCOUT_OOB_ADDR"))
	if err != nil {
		return nil, nil // no listener → no blind-SSRF detection, not a scan error
	}
	defer lis.Close()

	// Inject a unique callback per spot.
	tokenOf := map[string]injectable{}
	for _, in := range spots {
		tok := oob.NewToken()
		mutated, perr := withParam(in.rawURL, in.param, lis.URL(tok))
		if perr != nil {
			continue
		}
		if _, gerr := get(ctx, mutated); gerr != nil {
			continue
		}
		tokenOf[tok] = in
	}

	// Give the target a moment to make the out-of-band request.
	select {
	case <-time.After(oobGrace):
	case <-ctx.Done():
	}

	var out []core.Finding
	reported := map[string]bool{}
	for tok, in := range tokenOf {
		hits := lis.Hits(tok)
		if len(hits) == 0 {
			continue
		}
		key := in.rawURL + "\x00" + in.param
		if reported[key] {
			continue
		}
		reported[key] = true
		out = append(out, core.Finding{
			Title:      "Blind server-side request forgery in parameter " + in.param,
			Category:   core.CategoryApp,
			Severity:   core.SeverityHigh,
			Confidence: core.ConfidenceConfirmed, // the target called Scout's listener
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Matched: "target made an out-of-band request to Scout's OAST listener from " + hits[0].RemoteAddr,
				Notes:   "the fetched URL was a Scout-generated callback; the inbound hit confirms the server fetched it",
			},
			CWE:         []string{"CWE-918"},
			OWASP:       []string{"A10:2021"},
			Remediation: RemediationSSRF,
		})
	}
	return out, nil
}
