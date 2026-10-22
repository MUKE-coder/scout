package scoring

import (
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func TestHardCaps(t *testing.T) {
	internalHigh := f(core.CategoryApp, core.SeverityHigh)
	internalHigh.Asset.Exposure = core.ExposureInternal

	likelyCritical := f(core.CategoryApp, core.SeverityCritical)
	likelyCritical.Confidence = core.ConfidenceLikely

	expired := f(core.CategoryTLS, core.SeverityLow)
	expired.Tags = []string{core.TagExpiredCert}

	secret := f(core.CategoryCode, core.SeverityLow)
	secret.Tags = []string{core.TagExposedSecret}

	internalSecret := secret
	internalSecret.Asset.Exposure = core.ExposureInternal

	acceptedCritical := f(core.CategoryApp, core.SeverityCritical)
	acceptedCritical.Status = core.StatusAcceptedRisk

	cases := []struct {
		name      string
		finding   core.Finding
		wantGrade string // grade with only this finding, all else perfect
		wantCap   bool
	}{
		{"confirmed critical caps at F", f(core.CategoryHeaders, core.SeverityCritical), "F", true},
		{"likely critical is not capped", likelyCritical, "", false},
		{"confirmed high internet caps at C", f(core.CategoryHeaders, core.SeverityHigh), "C", true},
		{"confirmed high internal is not capped", internalHigh, "", false},
		{"expired cert caps at D", expired, "D", true},
		{"exposed public secret caps at D", secret, "D", true},
		{"internal secret is not capped", internalSecret, "", false},
		{"accepted-risk critical is not capped", acceptedCritical, "", false},
	}
	for _, c := range cases {
		r := Score([]core.Finding{c.finding}, Options{})
		if c.wantCap != (len(r.Caps) > 0) {
			t.Errorf("%s: caps = %+v", c.name, r.Caps)
			continue
		}
		if c.wantCap {
			if r.Grade != c.wantGrade {
				t.Errorf("%s: grade = %s (score %v, uncapped %v), want %s", c.name, r.Grade, r.Score, r.Uncapped, c.wantGrade)
			}
			if r.Score > r.Uncapped {
				t.Errorf("%s: cap raised the score", c.name)
			}
		}
	}
}

func TestWorstCapWins(t *testing.T) {
	expired := f(core.CategoryTLS, core.SeverityLow)
	expired.Tags = []string{core.TagExpiredCert}
	r := Score([]core.Finding{expired, f(core.CategoryApp, core.SeverityCritical), f(core.CategoryAPI, core.SeverityHigh)}, Options{})
	if r.Grade != "F" || r.Caps[0].Grade != "F" || len(r.Caps) != 3 {
		t.Fatalf("grade = %s caps = %+v", r.Grade, r.Caps)
	}
}

func TestCapNeverRaisesLowScore(t *testing.T) {
	var many []core.Finding
	for range 10 {
		many = append(many, f(core.CategoryApp, core.SeverityHigh))
	}
	r := Score(many, Options{Assessed: []core.Category{core.CategoryApp}})
	if r.Score != r.Uncapped || r.Grade != "F" {
		t.Fatalf("score %v uncapped %v grade %s", r.Score, r.Uncapped, r.Grade)
	}
}
