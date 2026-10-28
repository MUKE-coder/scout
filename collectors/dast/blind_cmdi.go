package dast

import (
	"context"
	"os"
	"time"

	"github.com/MUKE-coder/scout/core"
	"github.com/MUKE-coder/scout/oob"
)

// BlindCommandInjection confirms OS command injection out-of-band: it injects a
// benign command that fetches Scout's own OAST listener (curl/wget to a tokenized
// URL) behind shell metacharacters, and reports a parameter when the listener is
// called back. This catches the *blind* case app.cmd-injection cannot — where the
// command runs but its output never returns in the response.
//
// Detection only: the injected command does nothing but GET Scout's listener (no
// destructive action), and the inbound hit is what confirms execution. Reachability
// is the same as blind SSRF — local works out of the box, remote needs
// SCOUT_OOB_ADDR.
type BlindCommandInjection struct{}

func (BlindCommandInjection) ID() string              { return "app.blind-cmd-injection" }
func (BlindCommandInjection) Category() core.Category { return core.CategoryApp }
func (BlindCommandInjection) Mode() core.Mode         { return core.ModeActive }
func (BlindCommandInjection) Description() string {
	return "A parameter reaches an OS command, confirmed out-of-band (OAST)"
}
func (BlindCommandInjection) OWASP() []string { return []string{"A03:2021"} }
func (BlindCommandInjection) ASVS() []string  { return []string{"V5.3.8"} }

func (c BlindCommandInjection) Run(ctx context.Context, t core.Target) ([]core.Finding, error) {
	res, err := discover(ctx, t)
	if err != nil || res == nil {
		return nil, err
	}
	spots := allParams(res)
	if len(spots) == 0 {
		return nil, nil
	}

	lis, err := oob.Start(ctx, os.Getenv("SCOUT_OOB_ADDR"))
	if err != nil {
		return nil, nil
	}
	defer lis.Close()

	tokenOf := map[string]injectable{}
	for _, in := range spots {
		tok := oob.NewToken()
		cb := lis.URL(tok)
		injected := false
		// Benign fetches of our own listener, behind the shell metacharacters that
		// break out of a command context. If any reaches a shell, the server makes
		// the outbound request. Covers POSIX sh and Windows cmd separators.
		for _, payload := range []string{
			"x; curl -s " + cb,
			"x | curl -s " + cb,
			"x`curl -s " + cb + "`",
			"x$(curl -s " + cb + ")",
			"x && curl -s " + cb,
			"x & curl -s " + cb,
			"x; wget -q -O- " + cb,
		} {
			mutated, perr := withParam(in.rawURL, in.param, payload)
			if perr != nil {
				continue
			}
			if _, gerr := get(ctx, mutated); gerr == nil {
				injected = true
			}
		}
		if injected {
			tokenOf[tok] = in
		}
	}

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
			Title:      "Blind OS command injection in parameter " + in.param,
			Category:   core.CategoryApp,
			Severity:   core.SeverityCritical,
			Confidence: core.ConfidenceConfirmed, // the injected command called Scout's listener
			Asset:      assetFor(t, in.rawURL),
			Location:   in.param,
			Evidence: core.Evidence{
				Matched: "injected command made an out-of-band request to Scout's OAST listener from " + hits[0].RemoteAddr,
				Notes:   "a benign curl/wget to a Scout-generated URL ran via shell metacharacters; the inbound hit confirms command execution",
			},
			CWE:         []string{"CWE-78"},
			OWASP:       []string{"A03:2021"},
			Remediation: RemediationCmdInjection,
		})
	}
	return out, nil
}
