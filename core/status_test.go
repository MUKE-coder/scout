package core

import (
	"testing"
	"time"
)

func TestIsOpenAt(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		name string
		f    Finding
		want bool
	}{
		{"open", Finding{Status: StatusOpen}, true},
		{"unset", Finding{}, true},
		{"fixed", Finding{Status: StatusFixed}, false},
		{"false positive", Finding{Status: StatusFalsePositive}, false},
		{"accepted forever", Finding{Status: StatusAcceptedRisk}, false},
		{"accepted until later", Finding{Status: StatusAcceptedRisk, StatusUntil: &future}, false},
		{"acceptance expired", Finding{Status: StatusAcceptedRisk, StatusUntil: &past}, true},
		{"expires exactly now", Finding{Status: StatusAcceptedRisk, StatusUntil: &now}, true},
	}
	for _, c := range cases {
		if got := c.f.IsOpenAt(now); got != c.want {
			t.Errorf("%s: IsOpenAt = %v, want %v", c.name, got, c.want)
		}
	}
}
